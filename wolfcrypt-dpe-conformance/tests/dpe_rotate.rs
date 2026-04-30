//! DPE engine RotateContext command tests.

mod helpers;

use caliptra_cfi_lib::CfiCounter;
use caliptra_dpe::commands::{
    CommandExecution, DeriveContextCmd, DeriveContextFlags, RotateCtxCmd, RotateCtxFlags,
    SignFlags, SignP384Cmd,
};
use caliptra_dpe::context::ContextHandle;
use caliptra_dpe::dpe_instance::DpeInstance;
use caliptra_dpe::response::{Response, SignResp};
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

fn sign_with_handle(
    dpe: &mut DpeInstance,
    env: &mut caliptra_dpe::dpe_instance::DpeEnv<impl caliptra_dpe::dpe_instance::DpeTypes>,
    handle: ContextHandle,
    label: [u8; 48],
    digest: [u8; 48],
) -> ([u8; 48], [u8; 48], ContextHandle) {
    let cmd = SignP384Cmd {
        handle,
        label,
        flags: SignFlags::empty(),
        digest,
    };
    match cmd.execute(dpe, env, LOCALITY).unwrap() {
        Response::Sign(SignResp::P384(resp)) => (resp.sig_r, resp.sig_s, resp.new_context_handle),
        _ => panic!("Expected Sign P384, got unexpected response"),
    }
}

#[test]
fn rotate_changes_handle() {
    CfiCounter::reset_for_test();
    let support = Support::AUTO_INIT | Support::ROTATE_CONTEXT;
    let mut state = State::new(support, DpeFlags::empty());
    let mut env = dpe_harness::make_wolf_env(&mut state);
    let mut dpe = DpeInstance::new(&mut env, DpeProfile::P384Sha384).unwrap();

    let child = derive_child(&mut dpe, &mut env);

    // Rotate the child handle.
    let rotate_cmd = RotateCtxCmd {
        handle: child,
        flags: RotateCtxFlags::empty(),
    };
    let new_handle = match rotate_cmd.execute(&mut dpe, &mut env, LOCALITY).unwrap() {
        Response::RotateCtx(resp) => resp.handle,
        _ => panic!("Expected RotateCtx, got unexpected response"),
    };

    // Old handle should be invalid.
    let sign_old = SignP384Cmd {
        handle: child,
        label: [0; 48],
        flags: SignFlags::empty(),
        digest: [0xBB; 48],
    };
    assert!(
        sign_old.execute(&mut dpe, &mut env, LOCALITY).is_err(),
        "Old handle should be invalid after rotation"
    );

    // New handle should work.
    let (r, s, _) = sign_with_handle(&mut dpe, &mut env, new_handle, [0; 48], [0xBB; 48]);
    assert!(
        r.iter().any(|&b| b != 0),
        "Sign with rotated handle should produce non-zero r"
    );
}

#[test]
fn rotate_preserves_key() {
    CfiCounter::reset_for_test();
    let support = Support::AUTO_INIT | Support::ROTATE_CONTEXT;

    let mut state = State::new(support, DpeFlags::empty());
    let mut env = dpe_harness::make_wolf_env(&mut state);
    let mut dpe = DpeInstance::new(&mut env, DpeProfile::P384Sha384).unwrap();
    let child = derive_child(&mut dpe, &mut env);

    // Sign before rotation.
    let (r_before, s_before, handle_after_sign) =
        sign_with_handle(&mut dpe, &mut env, child, [0xAA; 48], [0xBB; 48]);
    assert!(
        r_before.iter().any(|&b| b != 0),
        "Pre-rotation sig_r should be non-zero"
    );

    // Rotate the handle.
    let rotate_cmd = RotateCtxCmd {
        handle: handle_after_sign,
        flags: RotateCtxFlags::empty(),
    };
    let new_handle = match rotate_cmd.execute(&mut dpe, &mut env, LOCALITY).unwrap() {
        Response::RotateCtx(resp) => resp.handle,
        _ => panic!("Expected RotateCtx, got unexpected response"),
    };

    // Sign after rotation should still succeed (key is preserved).
    let (r_after, s_after, _) =
        sign_with_handle(&mut dpe, &mut env, new_handle, [0xAA; 48], [0xBB; 48]);
    assert!(
        r_after.iter().any(|&b| b != 0),
        "Post-rotation sig_r should be non-zero"
    );
    assert!(
        s_after.iter().any(|&b| b != 0),
        "Post-rotation sig_s should be non-zero"
    );
}

#[test]
fn rotate_invalid_handle_fails() {
    CfiCounter::reset_for_test();
    let support = Support::AUTO_INIT | Support::ROTATE_CONTEXT;
    let mut state = State::new(support, DpeFlags::empty());
    let mut env = dpe_harness::make_wolf_env(&mut state);
    let mut dpe = DpeInstance::new(&mut env, DpeProfile::P384Sha384).unwrap();

    let bad_handle = ContextHandle([0xDE; 16]);
    let rotate_cmd = RotateCtxCmd {
        handle: bad_handle,
        flags: RotateCtxFlags::empty(),
    };
    let result = rotate_cmd.execute(&mut dpe, &mut env, LOCALITY);
    assert!(result.is_err(), "Rotating invalid handle should fail");
}

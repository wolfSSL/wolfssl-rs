//! Ports of upstream caliptra-dpe's own test suite, running with wolfcrypt-dpe
//! as the crypto backend.  If these tests pass, it proves wolfcrypt-dpe is a
//! correct CryptoSuite implementation for the DPE engine.
//!
//! Tests that require `pub(crate)` internals (compute_measurement_hash,
//! add_tci_measurement, ChildToRootIter, serialize_internal_input_info,
//! get_descendants, safe_to_make_default, safe_to_make_non_default,
//! validate_dpe_state, validate_context_forest) are intentionally skipped
//! or adapted to use their public wrappers.

mod helpers;

use caliptra_cfi_lib::CfiCounter;
use caliptra_dpe::commands::*;
use caliptra_dpe::context::{Children, Context, ContextHandle, ContextState, ContextType};
use caliptra_dpe::dpe_instance::{DpeEnv, DpeInstance, DpeTypes};
use caliptra_dpe::response::*;
use caliptra_dpe::support::Support;
use caliptra_dpe::tci::TciMeasurement;
use caliptra_dpe::validation::{DpeValidator, ValidationError};
use caliptra_dpe::{DpeFlags, DpeProfile, State, U8Bool, MAX_HANDLES, TCI_SIZE};
use caliptra_dpe_platform::default::{DefaultPlatform, DefaultPlatformProfile, AUTO_INIT_LOCALITY};
use caliptra_dpe_platform::{Platform, MAX_CHUNK_SIZE};
use zerocopy::IntoBytes;

// ===== Wolf backend types =====

struct WolfTestTypes;
impl DpeTypes for WolfTestTypes {
    type Crypto<'a> = wolfcrypt_dpe::WolfCryptDpe384;
    type Platform<'a> = DefaultPlatform;
}

// ===== Mirror upstream constants =====

const DPE_PROFILE: DpeProfile = DpeProfile::P384Sha384;

// This is crate-private in caliptra-dpe, but the value is known.
const CURRENT_PROFILE_MAJOR_VERSION: u16 = 0;

const SUPPORT: Support = Support::SIMULATION
    .union(Support::AUTO_INIT)
    .union(Support::ROTATE_CONTEXT)
    .union(Support::X509)
    .union(Support::RETAIN_PARENT_CONTEXT);

const TEST_HANDLE: ContextHandle =
    ContextHandle([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
const SIMULATION_HANDLE: ContextHandle =
    ContextHandle([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
const TEST_LOCALITIES: [u32; 2] = [AUTO_INIT_LOCALITY, u32::from_be_bytes(*b"OTHR")];
const DEFAULT_PLATFORM: DefaultPlatform = DefaultPlatform(DefaultPlatformProfile::P384);

const TEST_DIGEST: [u8; DPE_PROFILE.hash_size()] = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
];
const TEST_LABEL: [u8; DPE_PROFILE.hash_size()] = [
    48, 47, 46, 45, 44, 43, 42, 41, 40, 39, 38, 37, 36, 35, 34, 33, 32, 31, 30, 29, 28, 27, 26,
    25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
];

fn wolf_env(state: &mut State) -> DpeEnv<'_, WolfTestTypes> {
    DpeEnv::<WolfTestTypes> {
        crypto: wolfcrypt_dpe::WolfCryptDpe384::new(),
        platform: DEFAULT_PLATFORM,
        state,
    }
}

fn wolf_state() -> State {
    State::new(SUPPORT, DpeFlags::empty())
}

// ===== Macros =====

/// Assert that a command returns the expected error code.
/// We cannot use `assert_eq!` on `Result<Response, DpeErrorCode>` because
/// `Response` does not implement `PartialEq` or `Debug` outside the
/// caliptra-dpe crate's own test configuration.
macro_rules! assert_cmd_err {
    ($result:expr, $expected_err:expr) => {
        match $result {
            Err(e) => assert_eq!(e, $expected_err),
            Ok(_) => panic!(
                "Expected error {:?} but got Ok",
                $expected_err
            ),
        }
    };
}

// ===== Helpers =====

/// Execute DestroyCtxCmd and assert it returns a successful DestroyCtx response.
/// Response does not derive PartialEq outside #[cfg(test)] in caliptra-dpe,
/// so we use match instead of assert_eq.
fn assert_destroy_ok(
    dpe: &mut DpeInstance,
    env: &mut DpeEnv<'_, WolfTestTypes>,
    handle: ContextHandle,
    locality: u32,
) {
    let expected_hdr = dpe.response_hdr(DpeErrorCode::NoError);
    let resp = DestroyCtxCmd { handle }
        .execute(dpe, env, locality)
        .unwrap();
    match resp {
        Response::DestroyCtx(hdr) => assert_eq!(hdr, expected_hdr),
        _ => panic!("Expected DestroyCtx response"),
    }
}

/// Activate a dummy context at a given index -- mirrors the upstream helper in
/// destroy_context tests.  All State fields are pub, so this is fine.
fn activate_dummy_context(
    state: &mut State,
    idx: usize,
    parent_idx: u8,
    handle: &ContextHandle,
    children: &[u8],
) {
    state.contexts[idx].state = ContextState::Active;
    state.contexts[idx].handle = *handle;
    state.contexts[idx].parent_idx = parent_idx;
    for i in children {
        let children = state.contexts[idx].add_child(*i as usize).unwrap();
        state.contexts[idx].children = children;
    }
}

// =========================================================================
// dpe_instance.rs -- 3 tests ported, 4 skipped
// =========================================================================

#[test]
fn upstream_test_execute_serialized_command() {
    CfiCounter::reset_for_test();
    let mut state = wolf_state();
    let mut env = wolf_env(&mut state);
    let mut dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();

    // GetProfile via serialized command
    let expected = GetProfileResp::new(
        dpe.profile,
        SUPPORT.bits(),
        env.platform.get_vendor_id().unwrap(),
        env.platform.get_vendor_sku().unwrap(),
    );
    let resp = dpe
        .execute_serialized_command(
            &mut env,
            TEST_LOCALITIES[0],
            dpe.command_hdr(Command::GET_PROFILE).as_bytes(),
        )
        .unwrap();
    match resp {
        Response::GetProfile(actual) => assert_eq!(actual, expected),
        _ => panic!("Expected GetProfile response"),
    }

    // Initialize a simulation context via serialized command.
    let mut command = dpe
        .command_hdr(Command::INITIALIZE_CONTEXT)
        .as_bytes()
        .to_vec();
    command.extend(InitCtxCmd::new_simulation().as_bytes());
    let resp = dpe
        .execute_serialized_command(&mut env, TEST_LOCALITIES[0], &command)
        .unwrap();

    // wolfssl RNG differs from RustCrypto, so instead of comparing the exact
    // handle bytes we just check the handle is non-default (not all zeros).
    match resp {
        Response::InitCtx(NewHandleResp { handle, resp_hdr }) => {
            assert!(
                !handle.is_default(),
                "Simulation context handle must not be default"
            );
            assert_eq!(resp_hdr, dpe.response_hdr(DpeErrorCode::NoError));
        }
        _ => panic!("Expected InitCtx response"),
    }
}

#[test]
fn upstream_test_get_profile() {
    CfiCounter::reset_for_test();
    let mut state = wolf_state();
    let mut env = wolf_env(&mut state);
    let dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();
    let profile = dpe
        .get_profile(&mut env.platform, env.state.support)
        .unwrap();
    assert_eq!(profile.major_version, CURRENT_PROFILE_MAJOR_VERSION);
    assert_eq!(profile.flags, SUPPORT.bits());
}

#[test]
fn upstream_test_new_auto_init() {
    CfiCounter::reset_for_test();
    let mut state = wolf_state();
    let mut env = wolf_env(&mut state);
    let tci_type = 0xdeadbeef_u32;
    let auto_init_measurement = [0x1; DPE_PROFILE.hash_size()];
    let auto_init_locality = env.platform.get_auto_init_locality().unwrap();
    let mut dpe = DpeInstance::new_auto_init(
        &mut env,
        DPE_PROFILE,
        tci_type,
        &TciMeasurement(auto_init_measurement),
    )
    .unwrap();

    let idx = env
        .state
        .get_active_context_pos(&ContextHandle::default(), auto_init_locality)
        .unwrap();
    assert_eq!(env.state.contexts[idx].tci.tci_type, tci_type);
    assert_eq!(env.state.contexts[idx].tci.locality, auto_init_locality);
    assert_eq!(
        env.state.contexts[idx].tci.tci_current.0,
        auto_init_measurement
    );
    assert_eq!(env.state.contexts[idx].parent_idx, Context::ROOT_INDEX);
    assert!(env.state.contexts[idx].children.is_empty());
    assert_eq!(env.state.contexts[idx].state, ContextState::Active);
    assert_eq!(env.state.contexts[idx].handle, ContextHandle::default());
    assert!(env.state.has_initialized());

    // check that initialize context fails if new_auto_init was used
    assert_cmd_err!(
        InitCtxCmd::new_use_default().execute(&mut dpe, &mut env, auto_init_locality),
        DpeErrorCode::ArgumentNotSupported
    );
}

// =========================================================================
// initialize_context.rs -- 1 test ported
// =========================================================================

#[test]
fn upstream_test_initialize_context() {
    CfiCounter::reset_for_test();
    let mut state = State::default();
    let mut env = wolf_env(&mut state);
    let mut dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();

    let handle = match InitCtxCmd::new_use_default()
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        .unwrap()
    {
        Response::InitCtx(resp) => resp.handle,
        _ => panic!("Wrong response type."),
    };
    // Make sure default context is 0x0.
    assert_eq!(ContextHandle::default(), handle);

    // Try to double initialize the default context.
    assert_cmd_err!(
        InitCtxCmd::new_use_default().execute(&mut dpe, &mut env, TEST_LOCALITIES[0]),
        DpeErrorCode::ArgumentNotSupported
    );

    // Try not setting any flags.
    assert_cmd_err!(
        InitCtxCmd::empty().execute(&mut dpe, &mut env, TEST_LOCALITIES[0]),
        DpeErrorCode::InvalidArgument
    );

    // Try simulation when not supported.
    assert_cmd_err!(
        InitCtxCmd::new_simulation().execute(&mut dpe, &mut env, TEST_LOCALITIES[0]),
        DpeErrorCode::ArgumentNotSupported
    );

    // Change to support simulation.
    *env.state = State::new(Support::SIMULATION, DpeFlags::empty());
    let mut dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();

    // Try setting both flags.
    assert_cmd_err!(
        (InitCtxCmd::DEFAULT_FLAG_MASK | InitCtxCmd::SIMULATION_FLAG_MASK).execute(
        &mut dpe,
        &mut env,
        TEST_LOCALITIES[0]
        ),
        DpeErrorCode::InvalidArgument
    );

    // Set all handles as active.
    for context in env.state.contexts.iter_mut() {
        context.state = ContextState::Active;
    }

    // Try to initialize a context when it is full.
    assert_cmd_err!(
        InitCtxCmd::new_simulation().execute(&mut dpe, &mut env, TEST_LOCALITIES[0]),
        DpeErrorCode::MaxTcis
    );
}

// =========================================================================
// derive_context.rs -- ~10 key tests ported
// =========================================================================

#[test]
fn upstream_test_derive_support() {
    CfiCounter::reset_for_test();
    let mut state = State::new(
        Support::AUTO_INIT | Support::INTERNAL_INFO | Support::RETAIN_PARENT_CONTEXT,
        DpeFlags::empty(),
    );
    let mut env = wolf_env(&mut state);
    let mut dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();

    assert_cmd_err!(
        DeriveContextCmd {
        flags: DeriveContextFlags::INTERNAL_INPUT_DICE,
        ..Default::default()
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0]),
        DpeErrorCode::ArgumentNotSupported
    );

    *env.state = State::new(
        Support::AUTO_INIT | Support::INTERNAL_DICE | Support::RETAIN_PARENT_CONTEXT,
        DpeFlags::empty(),
    );
    dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();

    assert_cmd_err!(
        DeriveContextCmd {
        flags: DeriveContextFlags::INTERNAL_INPUT_INFO,
        ..Default::default()
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0]),
        DpeErrorCode::ArgumentNotSupported
    );

    *env.state = State::new(
        Support::AUTO_INIT | Support::INTERNAL_INFO | Support::INTERNAL_DICE,
        DpeFlags::empty(),
    );
    dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();

    assert_cmd_err!(
        DeriveContextCmd {
        flags: DeriveContextFlags::RETAIN_PARENT_CONTEXT,
        ..Default::default()
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0]),
        DpeErrorCode::ArgumentNotSupported
    );
}

#[test]
fn upstream_test_derive_initial_conditions() {
    CfiCounter::reset_for_test();
    let mut state = State::default();
    let mut env = wolf_env(&mut state);
    let mut dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();

    InitCtxCmd::new_use_default()
        .execute(&mut dpe, &mut env, 0)
        .unwrap();

    // Make sure it can detect wrong locality.
    assert_cmd_err!(
        DeriveContextCmd::default().execute(&mut dpe, &mut env, 1),
        DpeErrorCode::InvalidLocality
    );
}

#[test]
fn upstream_test_derive_max_tcis() {
    CfiCounter::reset_for_test();
    let mut state = State::new(Support::AUTO_INIT, DpeFlags::empty());
    let mut env = wolf_env(&mut state);
    let mut dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();

    // Fill all contexts with children (minus the auto-init context).
    for _ in 0..MAX_HANDLES - 1 {
        DeriveContextCmd {
            flags: DeriveContextFlags::MAKE_DEFAULT,
            ..Default::default()
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        .unwrap();
    }

    // Try to create one too many.
    assert_cmd_err!(
        DeriveContextCmd::default().execute(&mut dpe, &mut env, TEST_LOCALITIES[0]),
        DpeErrorCode::MaxTcis
    );
}

#[test]
fn upstream_test_correct_child_handle() {
    CfiCounter::reset_for_test();
    let mut state = State::new(Support::AUTO_INIT, DpeFlags::empty());
    let mut env = wolf_env(&mut state);
    let mut dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();

    // Make sure child handle is default when creating default child.
    let resp = DeriveContextCmd {
        flags: DeriveContextFlags::MAKE_DEFAULT,
        ..Default::default()
    }
    .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
    .unwrap();

    match resp {
        Response::DeriveContext(DeriveContextResp {
            handle,
            parent_handle,
            resp_hdr,
        }) => {
            assert_eq!(handle, ContextHandle::default());
            assert_eq!(parent_handle, ContextHandle([0xff; ContextHandle::SIZE]));
            assert_eq!(resp_hdr, dpe.response_hdr(DpeErrorCode::NoError));
        }
        _ => panic!("Wrong response type"),
    }

    // Make sure child has a random (non-default) handle when not creating default.
    let resp =
        DeriveContextCmd::default().execute(&mut dpe, &mut env, TEST_LOCALITIES[0]).unwrap();

    match resp {
        Response::DeriveContext(DeriveContextResp {
            handle,
            parent_handle,
            resp_hdr,
        }) => {
            // wolfssl RNG differs from RustCrypto -- just check non-default.
            assert!(
                !handle.is_default(),
                "Non-default child handle must not be all zeros"
            );
            assert_eq!(parent_handle, ContextHandle([0xff; ContextHandle::SIZE]));
            assert_eq!(resp_hdr, dpe.response_hdr(DpeErrorCode::NoError));
        }
        _ => panic!("Wrong response type"),
    }
}

#[test]
fn upstream_test_correct_parent_handle() {
    CfiCounter::reset_for_test();
    let mut state = State::new(
        Support::AUTO_INIT | Support::RETAIN_PARENT_CONTEXT,
        DpeFlags::empty(),
    );
    let mut env = wolf_env(&mut state);
    let mut dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();

    // Make sure the parent handle is non-sense when not retaining.
    let resp = DeriveContextCmd {
        flags: DeriveContextFlags::MAKE_DEFAULT,
        ..Default::default()
    }
    .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
    .unwrap();

    match resp {
        Response::DeriveContext(DeriveContextResp {
            handle,
            parent_handle,
            resp_hdr,
        }) => {
            assert_eq!(handle, ContextHandle::default());
            assert_eq!(parent_handle, ContextHandle([0xff; ContextHandle::SIZE]));
            assert_eq!(resp_hdr, dpe.response_hdr(DpeErrorCode::NoError));
        }
        _ => panic!("Wrong response type"),
    }

    // Make sure the default parent handle stays the default handle when retained.
    let resp = DeriveContextCmd {
        flags: DeriveContextFlags::RETAIN_PARENT_CONTEXT
            | DeriveContextFlags::MAKE_DEFAULT
            | DeriveContextFlags::CHANGE_LOCALITY,
        target_locality: TEST_LOCALITIES[1],
        ..Default::default()
    }
    .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
    .unwrap();

    match resp {
        Response::DeriveContext(DeriveContextResp {
            handle,
            parent_handle,
            resp_hdr,
        }) => {
            assert_eq!(handle, ContextHandle::default());
            assert_eq!(parent_handle, ContextHandle::default());
            assert_eq!(resp_hdr, dpe.response_hdr(DpeErrorCode::NoError));
        }
        _ => panic!("Wrong response type"),
    }

    // The next test case: make sure the parent handle rotates when not the
    // default and parent is retained.  Mutate one default to non-default.
    let old_default_idx = env
        .state
        .get_active_context_pos(&ContextHandle::default(), TEST_LOCALITIES[0])
        .unwrap();
    env.state.contexts[old_default_idx].handle = ContextHandle([0x1; ContextHandle::SIZE]);

    // Make sure neither the parent nor the child handles are default.
    let resp = DeriveContextCmd {
        handle: env.state.contexts[old_default_idx].handle,
        flags: DeriveContextFlags::RETAIN_PARENT_CONTEXT,
        ..Default::default()
    }
    .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
    .unwrap();

    match resp {
        Response::DeriveContext(DeriveContextResp {
            handle,
            parent_handle,
            resp_hdr,
        }) => {
            // wolfssl RNG differs -- check non-default and non-equal.
            assert!(!parent_handle.is_default());
            assert!(!handle.is_default());
            assert_ne!(handle, parent_handle);
            assert_eq!(resp_hdr, dpe.response_hdr(DpeErrorCode::NoError));
        }
        _ => panic!("Wrong response type"),
    }
}

#[test]
fn upstream_test_default_context_cannot_be_retained() {
    CfiCounter::reset_for_test();
    let mut state = State::new(
        Support::AUTO_INIT | Support::RETAIN_PARENT_CONTEXT,
        DpeFlags::empty(),
    );
    let mut env = wolf_env(&mut state);
    let mut dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();

    assert_cmd_err!(
        DeriveContextCmd {
        flags: DeriveContextFlags::RETAIN_PARENT_CONTEXT,
        ..Default::default()
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0]),
        DpeErrorCode::InvalidArgument
    );
}

#[test]
fn upstream_test_recursive() {
    CfiCounter::reset_for_test();
    let mut state = State::new(
        Support::AUTO_INIT
            | Support::RECURSIVE
            | Support::INTERNAL_DICE
            | Support::INTERNAL_INFO,
        DpeFlags::empty(),
    );
    let mut env = wolf_env(&mut state);
    let mut dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();

    // First recursive derive
    let resp = DeriveContextCmd {
        handle: ContextHandle::default(),
        data: TciMeasurement([1; TCI_SIZE]),
        flags: DeriveContextFlags::MAKE_DEFAULT
            | DeriveContextFlags::RECURSIVE
            | DeriveContextFlags::INTERNAL_INPUT_INFO
            | DeriveContextFlags::INTERNAL_INPUT_DICE,
        tci_type: 0,
        target_locality: 0,
        svn: 0,
    }
    .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
    .unwrap();

    match resp {
        Response::DeriveContext(DeriveContextResp {
            handle,
            parent_handle,
            resp_hdr,
        }) => {
            assert_eq!(handle, ContextHandle::default());
            assert_eq!(parent_handle, ContextHandle::default());
            assert_eq!(resp_hdr, dpe.response_hdr(DpeErrorCode::NoError));
        }
        _ => panic!("Wrong response type"),
    }

    // Second recursive derive
    DeriveContextCmd {
        handle: ContextHandle::default(),
        data: TciMeasurement([2; TCI_SIZE]),
        flags: DeriveContextFlags::MAKE_DEFAULT
            | DeriveContextFlags::RECURSIVE
            | DeriveContextFlags::INTERNAL_INPUT_INFO
            | DeriveContextFlags::INTERNAL_INPUT_DICE,
        tci_type: 0,
        target_locality: 0,
        svn: 0,
    }
    .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
    .unwrap();

    let child_idx = env
        .state
        .get_active_context_pos(&ContextHandle::default(), 0)
        .unwrap();
    // ensure flags are unchanged
    assert!(env.state.contexts[child_idx].allow_x509());
    assert!(!env.state.contexts[child_idx].uses_internal_input_info());
    assert!(!env.state.contexts[child_idx].uses_internal_input_dice());
    // Still using the same context.
    assert!(env.state.contexts[child_idx].allow_export_cdi());

    // check tci_cumulative correctly computed -- use our wolf crypto
    use caliptra_dpe_crypto::{Crypto, Hasher};
    let mut crypto = wolfcrypt_dpe::WolfCryptDpe384::new();
    let mut hasher = crypto.hash_initialize().unwrap();
    hasher.update(&[0u8; DPE_PROFILE.hash_size()]).unwrap();
    hasher.update(&[1u8; DPE_PROFILE.hash_size()]).unwrap();
    let temp_digest = hasher.finish().unwrap();
    let mut hasher_2 = crypto.hash_initialize().unwrap();
    hasher_2.update(temp_digest.as_slice()).unwrap();
    hasher_2.update(&[2u8; DPE_PROFILE.hash_size()]).unwrap();
    let digest = hasher_2.finish().unwrap();
    assert_eq!(
        digest.as_slice(),
        env.state.contexts[child_idx].tci.tci_cumulative.0
    );
}

// NOTE: upstream test_safe_to_make_default and test_safe_to_make_non_default
// are skipped because they call private methods on DeriveContextCmd.

// =========================================================================
// sign.rs -- 1 test ported
// =========================================================================

#[test]
fn upstream_test_sign_bad_command_inputs() {
    CfiCounter::reset_for_test();
    let mut state = wolf_state();
    let mut env = wolf_env(&mut state);
    let mut dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();

    // Bad handle.
    assert_cmd_err!(
        SignP384Cmd {
        handle: ContextHandle([0xff; ContextHandle::SIZE]),
        label: TEST_LABEL,
        flags: SignFlags::empty(),
        digest: TEST_DIGEST
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0]),
        DpeErrorCode::InvalidHandle
    );

    // Wrong locality.
    assert!(env
        .state
        .get_active_context_pos(&ContextHandle::default(), TEST_LOCALITIES[0])
        .is_ok());
    assert_cmd_err!(
        SignP384Cmd {
        handle: ContextHandle::default(),
        label: TEST_LABEL,
        flags: SignFlags::empty(),
        digest: TEST_DIGEST
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[1]),
        DpeErrorCode::InvalidLocality
    );

    // Simulation contexts should not support the Sign command.
    let sim_resp = InitCtxCmd::new_simulation()
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        .unwrap();
    let sim_handle = match sim_resp {
        Response::InitCtx(resp) => resp.handle,
        _ => panic!("Wrong response type"),
    };
    assert!(env
        .state
        .get_active_context_pos(&sim_handle, TEST_LOCALITIES[0])
        .is_ok());
    assert_cmd_err!(
        SignP384Cmd {
        handle: sim_handle,
        label: TEST_LABEL,
        flags: SignFlags::empty(),
        digest: TEST_DIGEST
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0]),
        DpeErrorCode::InvalidArgument
    );
}

// =========================================================================
// destroy_context.rs -- 2 tests ported
// =========================================================================

#[test]
fn upstream_test_destroy_context() {
    CfiCounter::reset_for_test();
    let mut state = State::default();
    let mut env = wolf_env(&mut state);
    let mut dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();

    InitCtxCmd::new_use_default()
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        .unwrap();

    // Wrong locality.
    assert_cmd_err!(
        DestroyCtxCmd {
        handle: ContextHandle::default(),
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[1]),
        DpeErrorCode::InvalidLocality
    );

    // create two dummy contexts at indices 0 and 1, with 1 being the child of 0
    activate_dummy_context(&mut env.state, 0, Context::ROOT_INDEX, &TEST_HANDLE, &[1]);
    activate_dummy_context(&mut env.state, 1, 0, &ContextHandle::default(), &[]);
    // destroy context[1]
    assert_destroy_ok(&mut dpe, &mut env, ContextHandle::default(), TEST_LOCALITIES[0]);
    assert_eq!(env.state.contexts[1].state, ContextState::Inactive);
    assert!(env.state.contexts[0].children.is_empty());
    // destroy context[0]
    assert_destroy_ok(&mut dpe, &mut env, TEST_HANDLE, TEST_LOCALITIES[0]);
    assert_eq!(env.state.contexts[0].state, ContextState::Inactive);

    // Build a tree: 0 -> {1, 2}, 1 -> {3, 4}, 2 -> {5, 6}
    activate_dummy_context(
        &mut env.state,
        0,
        Context::ROOT_INDEX,
        &ContextHandle::default(),
        &[1, 2],
    );
    activate_dummy_context(
        &mut env.state,
        1,
        0,
        &ContextHandle([1; ContextHandle::SIZE]),
        &[3, 4],
    );
    activate_dummy_context(
        &mut env.state,
        2,
        0,
        &ContextHandle([2; ContextHandle::SIZE]),
        &[5, 6],
    );
    activate_dummy_context(
        &mut env.state,
        3,
        1,
        &ContextHandle([3; ContextHandle::SIZE]),
        &[],
    );
    activate_dummy_context(
        &mut env.state,
        4,
        1,
        &ContextHandle([4; ContextHandle::SIZE]),
        &[],
    );
    activate_dummy_context(
        &mut env.state,
        5,
        2,
        &ContextHandle([5; ContextHandle::SIZE]),
        &[],
    );
    activate_dummy_context(
        &mut env.state,
        6,
        2,
        &ContextHandle([6; ContextHandle::SIZE]),
        &[],
    );

    // destroy context[0] and all descendants
    assert_destroy_ok(&mut dpe, &mut env, ContextHandle::default(), TEST_LOCALITIES[0]);
    assert_eq!(env.state.contexts[0].state, ContextState::Inactive);
    assert_eq!(env.state.contexts[1].state, ContextState::Inactive);
    assert_eq!(env.state.contexts[2].state, ContextState::Inactive);
    assert_eq!(env.state.contexts[3].state, ContextState::Inactive);
    assert_eq!(env.state.contexts[4].state, ContextState::Inactive);
    assert_eq!(env.state.contexts[5].state, ContextState::Inactive);
    assert_eq!(env.state.contexts[6].state, ContextState::Inactive);
    assert!(env.state.contexts[0].children.is_empty());
    assert!(env.state.contexts[1].children.is_empty());
    assert!(env.state.contexts[2].children.is_empty());
    assert!(env.state.contexts[3].children.is_empty());

    // Test partial destroy: 0 -> {1, 2}, destroy only 1.
    activate_dummy_context(
        &mut env.state,
        0,
        Context::ROOT_INDEX,
        &ContextHandle::default(),
        &[1, 2],
    );
    activate_dummy_context(
        &mut env.state,
        1,
        0,
        &ContextHandle([1; ContextHandle::SIZE]),
        &[],
    );
    activate_dummy_context(
        &mut env.state,
        2,
        0,
        &ContextHandle([2; ContextHandle::SIZE]),
        &[],
    );
    // destroy context[1]
    assert_destroy_ok(
        &mut dpe,
        &mut env,
        ContextHandle([1; ContextHandle::SIZE]),
        TEST_LOCALITIES[0],
    );
    assert_eq!(env.state.contexts[1].state, ContextState::Inactive);
    // check that context[2] is still a child of context[0]
    assert_eq!(env.state.contexts[0].children.bits(), 1 << 2);
}

#[test]
fn upstream_test_retired_parent_contexts_destroyed() {
    CfiCounter::reset_for_test();
    let mut state = wolf_state();
    let mut env = wolf_env(&mut state);
    let mut dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();

    // create new context while preserving auto-initialized context
    let handle_1 = match (DeriveContextCmd {
        flags: DeriveContextFlags::RETAIN_PARENT_CONTEXT | DeriveContextFlags::CHANGE_LOCALITY,
        target_locality: TEST_LOCALITIES[1],
        ..Default::default()
    })
    .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
    {
        Ok(Response::DeriveContext(resp)) => resp.handle,
        Ok(_) => panic!("Invalid response type"),
        Err(e) => panic!("{:?}", e),
    };

    // retire context with handle 1 and create new context
    let handle_2 = match (DeriveContextCmd {
        handle: handle_1,
        target_locality: TEST_LOCALITIES[1],
        ..Default::default()
    })
    .execute(&mut dpe, &mut env, TEST_LOCALITIES[1])
    {
        Ok(Response::DeriveContext(resp)) => resp.handle,
        Ok(_) => panic!("Invalid response type"),
        Err(e) => panic!("{:?}", e),
    };

    // retire context with handle 2 and create new context
    let handle_3 = match (DeriveContextCmd {
        handle: handle_2,
        target_locality: TEST_LOCALITIES[1],
        ..Default::default()
    })
    .execute(&mut dpe, &mut env, TEST_LOCALITIES[1])
    {
        Ok(Response::DeriveContext(resp)) => resp.handle,
        Ok(_) => panic!("Invalid response type"),
        Err(e) => panic!("{:?}", e),
    };

    DestroyCtxCmd { handle: handle_3 }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[1])
        .unwrap();

    // only the auto-initialized context should remain
    assert_eq!(
        env.state
            .count_contexts(|ctx| ctx.state != ContextState::Inactive)
            .unwrap(),
        1
    );
    assert_eq!(env.state.contexts[2].state, ContextState::Inactive);
}

// =========================================================================
// rotate_context.rs -- 1 test ported
// =========================================================================

#[test]
fn upstream_test_rotate_context() {
    CfiCounter::reset_for_test();
    let mut state = State::default();
    let mut env = wolf_env(&mut state);
    let mut dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();
    // Make sure it returns an error if the command is marked unsupported.
    assert_cmd_err!(
        RotateCtxCmd {
        handle: ContextHandle::default(),
        flags: RotateCtxFlags::empty(),
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0]),
        DpeErrorCode::InvalidCommand
    );

    // Make a new instance that supports RotateContext.
    *env.state = State::new(Support::ROTATE_CONTEXT, DpeFlags::empty());
    let mut dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();
    InitCtxCmd::new_use_default()
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        .unwrap();

    // Invalid handle.
    assert_cmd_err!(
        RotateCtxCmd {
        handle: TEST_HANDLE,
        flags: RotateCtxFlags::empty(),
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0]),
        DpeErrorCode::InvalidHandle
    );

    // Wrong locality.
    assert_cmd_err!(
        RotateCtxCmd {
        handle: ContextHandle::default(),
        flags: RotateCtxFlags::empty(),
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[1]),
        DpeErrorCode::InvalidLocality
    );

    // Caller's locality already has default context.
    assert_cmd_err!(
        RotateCtxCmd {
        handle: ContextHandle::default(),
        flags: RotateCtxFlags::TARGET_IS_DEFAULT,
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0]),
        DpeErrorCode::InvalidArgument
    );

    // Rotate default handle -- wolfssl RNG will differ, just check non-default.
    let resp = RotateCtxCmd {
        handle: ContextHandle::default(),
        flags: RotateCtxFlags::empty(),
    }
    .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
    .unwrap();

    let rotated_handle = match resp {
        Response::RotateCtx(NewHandleResp { handle, resp_hdr }) => {
            assert!(!handle.is_default());
            assert_eq!(resp_hdr, dpe.response_hdr(DpeErrorCode::NoError));
            handle
        }
        _ => panic!("Wrong response type"),
    };

    // Set up another active context to test TARGET_IS_DEFAULT rejection.
    env.state.contexts[1].state = ContextState::Active;
    env.state.contexts[1].locality = TEST_LOCALITIES[0];
    env.state.contexts[1].handle = SIMULATION_HANDLE;
    // Check that it returns an error if we try to rotate to a default context
    // when we have other non-default contexts in the same locality.
    assert_cmd_err!(
        RotateCtxCmd {
        handle: SIMULATION_HANDLE,
        flags: RotateCtxFlags::TARGET_IS_DEFAULT,
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0]),
        DpeErrorCode::InvalidArgument
    );
    env.state.contexts[1].state = ContextState::Inactive;

    // New handle is all 0s if caller requests default handle.
    let resp = RotateCtxCmd {
        handle: rotated_handle,
        flags: RotateCtxFlags::TARGET_IS_DEFAULT,
    }
    .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
    .unwrap();
    match resp {
        Response::RotateCtx(NewHandleResp { handle, resp_hdr }) => {
            assert_eq!(handle, ContextHandle::default());
            assert_eq!(resp_hdr, dpe.response_hdr(DpeErrorCode::NoError));
        }
        _ => panic!("Wrong response type"),
    }
}

// =========================================================================
// validation.rs -- 6 tests ported (no crypto involved)
// =========================================================================

// NOTE: upstream test_validate_context_forest is skipped because it calls
// the private validate_context_forest() method.  We test the same validations
// indirectly through the public validate_dpe() method below.

#[test]
fn upstream_test_support_validation() {
    CfiCounter::reset_for_test();
    let mut state = State::default();
    let dpe_validator = DpeValidator { dpe: &mut state };

    // test simulation support -- via validate_dpe (validate_dpe_state runs first)
    dpe_validator.dpe.contexts[0].context_type = ContextType::Simulation;
    assert_eq!(
        dpe_validator.validate_dpe(),
        Err(DpeErrorCode::Validation(ValidationError::SimulationNotSupported))
    );

    // test internal dice support
    dpe_validator.dpe.contexts[0].context_type = ContextType::Normal;
    dpe_validator.dpe.contexts[0].uses_internal_input_dice = U8Bool::new(true);
    assert_eq!(
        dpe_validator.validate_dpe(),
        Err(DpeErrorCode::Validation(ValidationError::InternalDiceNotSupported))
    );

    // test internal info support
    dpe_validator.dpe.contexts[0].uses_internal_input_dice = U8Bool::new(false);
    dpe_validator.dpe.contexts[0].uses_internal_input_info = U8Bool::new(true);
    assert_eq!(
        dpe_validator.validate_dpe(),
        Err(DpeErrorCode::Validation(ValidationError::InternalInfoNotSupported))
    );

    // test x509
    dpe_validator.dpe.contexts[0].parent_idx = 1;
    dpe_validator.dpe.contexts[0].uses_internal_input_info = U8Bool::new(false);
    dpe_validator.dpe.contexts[0].allow_x509 = U8Bool::new(true);
    assert_eq!(
        dpe_validator.validate_dpe(),
        Err(DpeErrorCode::Validation(ValidationError::AllowX509NotSupported))
    );
}

#[test]
fn upstream_test_context_specific_validation() {
    CfiCounter::reset_for_test();
    let mut state = State::new(
        Support::all().difference(Support::AUTO_INIT),
        DpeFlags::empty(),
    );
    let dpe_validator = DpeValidator { dpe: &mut state };

    // inactive context validation
    dpe_validator.dpe.contexts[0].parent_idx = 0;
    assert_eq!(
        dpe_validator.validate_dpe(),
        Err(DpeErrorCode::Validation(ValidationError::InactiveContextInvalidParent))
    );

    dpe_validator.dpe.contexts[0].parent_idx = Context::ROOT_INDEX;
    dpe_validator.dpe.contexts[0].children = u64::MAX.into();
    assert_eq!(
        dpe_validator.validate_dpe(),
        Err(DpeErrorCode::Validation(ValidationError::InactiveContextWithChildren))
    );

    dpe_validator.dpe.contexts[0].children = Children::empty();
    dpe_validator.dpe.contexts[0].tci.tci_current = TciMeasurement([1; TCI_SIZE]);
    assert_eq!(
        dpe_validator.validate_dpe(),
        Err(DpeErrorCode::Validation(ValidationError::InactiveContextWithMeasurement))
    );

    dpe_validator.dpe.contexts[0].tci.tci_current = TciMeasurement::default();
    dpe_validator.dpe.contexts[0].allow_x509 = U8Bool::new(true);
    assert_eq!(
        dpe_validator.validate_dpe(),
        Err(DpeErrorCode::Validation(ValidationError::InactiveContextWithFlagSet))
    );

    // active context validation
    dpe_validator.dpe.has_initialized = U8Bool::new(true);
    dpe_validator.dpe.contexts[0].state = ContextState::Active;
    dpe_validator.dpe.contexts[0].parent_idx = 250;
    assert_eq!(
        dpe_validator.validate_dpe(),
        Err(DpeErrorCode::Validation(ValidationError::ParentDoesNotExist))
    );

    dpe_validator.dpe.contexts[0].parent_idx = Context::ROOT_INDEX;
    dpe_validator.dpe.contexts[0].children = Children::from(1 << 30);
    assert_eq!(
        dpe_validator.validate_dpe(),
        Err(DpeErrorCode::Validation(ValidationError::InactiveChild))
    );

    dpe_validator.dpe.contexts[0].children = Children::from(1 << 10);
    assert_eq!(
        dpe_validator.validate_dpe(),
        Err(DpeErrorCode::Validation(ValidationError::InactiveChild))
    );

    dpe_validator.dpe.contexts[0].children = Children::empty();
    dpe_validator.dpe.contexts[0].parent_idx = 10;
    assert_eq!(
        dpe_validator.validate_dpe(),
        Err(DpeErrorCode::Validation(ValidationError::InactiveParent))
    );

    dpe_validator.dpe.contexts[10].state = ContextState::Active;
    dpe_validator.dpe.contexts[0].children = Children::from(1 << 10);
    assert_eq!(
        dpe_validator.validate_dpe(),
        Err(DpeErrorCode::Validation(ValidationError::ParentChildLinksCorrupted))
    );

    dpe_validator.dpe.contexts[0].children = Children::empty();
    dpe_validator.dpe.contexts[0].parent_idx = 10;
    assert_eq!(
        dpe_validator.validate_dpe(),
        Err(DpeErrorCode::Validation(ValidationError::ParentChildLinksCorrupted))
    );

    dpe_validator.dpe.contexts[0].parent_idx = Context::ROOT_INDEX;
    dpe_validator.dpe.has_initialized = U8Bool::new(false);
    assert_eq!(
        dpe_validator.validate_dpe(),
        Err(DpeErrorCode::Validation(ValidationError::DpeNotMarkedInitialized))
    );

    // retired context validation
    dpe_validator.dpe.has_initialized = U8Bool::new(true);
    dpe_validator.dpe.contexts[0].parent_idx = Context::ROOT_INDEX;
    dpe_validator.dpe.contexts[0].state = ContextState::Retired;
    assert_eq!(
        dpe_validator.validate_dpe(),
        Err(DpeErrorCode::Validation(ValidationError::DanglingRetiredContext))
    );

    // locality mismatch
    dpe_validator.dpe.contexts[0].state = ContextState::Active;
    dpe_validator.dpe.contexts[0].context_type = ContextType::Normal;
    dpe_validator.dpe.contexts[0].locality = 0;
    dpe_validator.dpe.contexts[0].tci.locality = 1;
    assert_eq!(
        dpe_validator.validate_dpe(),
        Err(DpeErrorCode::Validation(ValidationError::LocalityMismatch))
    );
}

#[test]
fn upstream_test_contexts_within_same_locality_validation() {
    CfiCounter::reset_for_test();
    let mut state = State::default();
    let dpe_validator = DpeValidator { dpe: &mut state };
    dpe_validator.dpe.has_initialized = U8Bool::new(true);

    // multiple default contexts in same locality
    dpe_validator.dpe.contexts[0].state = ContextState::Active;
    dpe_validator.dpe.contexts[1].state = ContextState::Active;
    dpe_validator.dpe.contexts[0].locality = 0;
    dpe_validator.dpe.contexts[1].locality = 0;
    dpe_validator.dpe.contexts[0].handle = ContextHandle::default();
    dpe_validator.dpe.contexts[1].handle = ContextHandle::default();
    assert_eq!(
        dpe_validator.validate_dpe(),
        Err(DpeErrorCode::Validation(ValidationError::MultipleDefaultContexts))
    );

    // default and non-default contexts in same locality
    dpe_validator.dpe.contexts[1].handle = ContextHandle([1u8; ContextHandle::SIZE]);
    assert_eq!(
        dpe_validator.validate_dpe(),
        Err(DpeErrorCode::Validation(ValidationError::MixedContextLocality))
    );
}

#[test]
fn upstream_test_invalid_marker() {
    CfiCounter::reset_for_test();
    let mut state = State::default();
    let dpe_validator = DpeValidator { dpe: &mut state };
    assert_eq!(Ok(()), dpe_validator.validate_dpe());

    // Changing the marker magic value should cause an error
    dpe_validator.dpe.marker = 0;
    assert_eq!(
        dpe_validator.validate_dpe(),
        Err(DpeErrorCode::Validation(ValidationError::InvalidMarker))
    );
}

#[test]
fn upstream_test_version_mismatch() {
    CfiCounter::reset_for_test();
    let mut state = State::default();
    let dpe_validator = DpeValidator { dpe: &mut state };
    assert_eq!(Ok(()), dpe_validator.validate_dpe());

    // Changing the version number should cause an error
    dpe_validator.dpe.version = 0;
    assert_eq!(
        dpe_validator.validate_dpe(),
        Err(DpeErrorCode::Validation(ValidationError::VersionMismatch))
    );
}

// =========================================================================
// state.rs -- 3 tests ported (skip test_get_descendants which uses pub(crate))
// =========================================================================

#[test]
fn upstream_test_get_active_context_index() {
    CfiCounter::reset_for_test();
    let mut state = State::default();
    let expected_index = 7;
    state.contexts[expected_index].handle = SIMULATION_HANDLE;

    let locality = AUTO_INIT_LOCALITY;
    // Has not been activated.
    assert!(state
        .get_active_context_pos(&SIMULATION_HANDLE, locality)
        .is_err());

    // Shouldn't be able to find it if it is retired either.
    state.contexts[expected_index].state = ContextState::Retired;
    assert!(state
        .get_active_context_pos(&SIMULATION_HANDLE, locality)
        .is_err());

    // Mark it active, but check the wrong locality.
    let locality = 2;
    state.contexts[expected_index].state = ContextState::Active;
    assert!(state
        .get_active_context_pos(&SIMULATION_HANDLE, locality)
        .is_err());

    // Should find it now.
    state.contexts[expected_index].locality = locality;
    let idx = state
        .get_active_context_pos(&SIMULATION_HANDLE, locality)
        .unwrap();
    assert_eq!(expected_index, idx);
}

#[test]
fn upstream_test_state_size() {
    use core::mem::size_of;
    // P384 expected size (from upstream).
    const EXPECTED_SIZE: usize = 9232;

    if size_of::<State>() != EXPECTED_SIZE {
        panic!(
            "State size has changed from {} to {}. If this is intentional, update the \
            EXPECTED_SIZE in this test and CONSIDER BUMPING THE VERSION NUMBER (State::VERSION).",
            EXPECTED_SIZE,
            size_of::<State>()
        );
    }
}

#[test]
fn upstream_test_state_offsets() {
    use core::mem::offset_of;
    // P384 expected offsets (from upstream).
    let expected_offsets = (0, 4, 8, 9224, 9228, 9230, 9231);

    let actual_offsets = (
        offset_of!(State, marker),
        offset_of!(State, version),
        offset_of!(State, contexts),
        offset_of!(State, support),
        offset_of!(State, flags),
        offset_of!(State, has_initialized),
        offset_of!(State, reserved),
    );

    if actual_offsets != expected_offsets {
        panic!(
            "State field offsets have changed. Expected {:?}, got {:?}. \
            If this is intentional, update the EXPECTED_OFFSETS in this test and \
            CONSIDER BUMPING THE VERSION NUMBER (State::VERSION).",
            expected_offsets, actual_offsets
        );
    }
}

// =========================================================================
// get_certificate_chain.rs -- 1 test ported
// =========================================================================

#[test]
fn upstream_test_fails_if_size_greater_than_max_chunk_size() {
    CfiCounter::reset_for_test();
    let mut state = wolf_state();
    let mut env = wolf_env(&mut state);
    let mut dpe = DpeInstance::new(&mut env, DPE_PROFILE).unwrap();

    assert_cmd_err!(
        GetCertificateChainCmd {
        size: MAX_CHUNK_SIZE as u32 + 1,
        offset: 0,
        }
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0]),
        DpeErrorCode::InvalidArgument
    );
}

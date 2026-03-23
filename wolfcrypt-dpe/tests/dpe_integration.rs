//! Integration test: run the caliptra-dpe engine with wolfcrypt-dpe as the
//! crypto backend. Proves the full stack works on x86_64 without RISC-V
//! hardware.

use caliptra_cfi_lib::CfiCounter;
use caliptra_dpe::commands::{CommandExecution, InitCtxCmd};
use caliptra_dpe::dpe_instance::{DpeEnv, DpeInstance, DpeTypes};
use caliptra_dpe::response::Response;
use caliptra_dpe::support::Support;
use caliptra_dpe::{DpeFlags, DpeProfile, State};
use caliptra_dpe_platform::default::{DefaultPlatform, DefaultPlatformProfile};

use wolfcrypt_dpe::WolfCryptDpe384;

/// Wire wolfcrypt-dpe into the DPE engine's type system.
struct WolfCryptDpeTypes;

impl DpeTypes for WolfCryptDpeTypes {
    type Crypto<'a> = WolfCryptDpe384;
    type Platform<'a> = DefaultPlatform;
}

const LOCALITY: u32 = 0;

fn make_env(state: &mut State) -> DpeEnv<'_, WolfCryptDpeTypes> {
    DpeEnv {
        crypto: WolfCryptDpe384::new(),
        platform: DefaultPlatform(DefaultPlatformProfile::P384),
        state,
    }
}

// ---------- Basic lifecycle ----------

#[test]
fn dpe_auto_init_with_wolfcrypt() {
    CfiCounter::reset_for_test();
    let support = Support::AUTO_INIT | Support::SIMULATION;
    let mut state = State::new(support, DpeFlags::empty());
    let mut env = make_env(&mut state);

    // DpeInstance::new with AUTO_INIT calls InitCtxCmd internally
    let dpe = DpeInstance::new(&mut env, DpeProfile::P384Sha384);
    assert!(dpe.is_ok(), "DpeInstance::new failed: {:?}", dpe.err());
}

#[test]
fn dpe_manual_init_with_wolfcrypt() {
    CfiCounter::reset_for_test();
    let support = Support::SIMULATION;
    let mut state = State::new(support, DpeFlags::empty());
    let mut env = make_env(&mut state);

    let mut dpe = DpeInstance::new(&mut env, DpeProfile::P384Sha384).unwrap();

    // Manually initialize a simulation context
    let result = InitCtxCmd::new_simulation().execute(&mut dpe, &mut env, LOCALITY);
    assert!(result.is_ok(), "InitCtxCmd failed: {:?}", result.err());

    match result.unwrap() {
        Response::InitCtx(resp) => {
            // Should get a non-default handle for simulation contexts
            assert_ne!(resp.handle.0, [0u8; 16]);
        }
        _ => panic!("Expected InitCtx response"),
    }
}

// ---------- Full DPE flow: init → derive → sign ----------

#[test]
fn dpe_derive_and_sign_with_wolfcrypt() {
    use caliptra_dpe::commands::DeriveContextCmd;
    use caliptra_dpe::commands::SignP384Cmd;
    use caliptra_dpe::context::ContextHandle;
    use caliptra_dpe::response::SignResp;
    use caliptra_dpe::tci::TciMeasurement;

    CfiCounter::reset_for_test();
    let support = Support::AUTO_INIT;
    let mut state = State::new(support, DpeFlags::empty());
    let mut env = make_env(&mut state);

    let mut dpe = DpeInstance::new(&mut env, DpeProfile::P384Sha384).unwrap();

    // Derive a child context from the default context.
    // Note: cannot use RETAIN_PARENT with the default context because
    // DPE requires a default context to be the sole context in its locality.
    let derive_cmd = DeriveContextCmd {
        handle: ContextHandle::default(),
        data: TciMeasurement([0x42u8; 48]),
        flags: caliptra_dpe::commands::DeriveContextFlags::empty(),
        tci_type: 0x12345678,
        target_locality: LOCALITY,
        svn: 0,
    };

    let result = derive_cmd.execute(&mut dpe, &mut env, LOCALITY);
    assert!(result.is_ok(), "DeriveContext failed: {:?}", result.err());

    let child_handle = match result.unwrap() {
        Response::DeriveContext(resp) => resp.handle,
        _ => panic!("Expected DeriveContext response"),
    };

    // Sign with the derived context
    let sign_cmd = SignP384Cmd {
        handle: child_handle,
        label: [0xAA; 48],
        flags: caliptra_dpe::commands::SignFlags::empty(),
        digest: [0xBB; 48],
    };

    let result = sign_cmd.execute(&mut dpe, &mut env, LOCALITY);
    assert!(result.is_ok(), "Sign failed: {:?}", result.err());

    match result.unwrap() {
        Response::Sign(SignResp::P384(resp)) => {
            // P-384 signature: r and s are 48 bytes each
            assert!(
                resp.sig_r.iter().any(|&b| b != 0),
                "Signature r component is all zeros"
            );
            assert!(
                resp.sig_s.iter().any(|&b| b != 0),
                "Signature s component is all zeros"
            );
        }
        _ => panic!("Expected Sign P384 response"),
    }
}

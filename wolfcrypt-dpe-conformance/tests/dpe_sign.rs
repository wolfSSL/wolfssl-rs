//! DPE engine Sign command tests.

mod helpers;

use caliptra_cfi_lib::CfiCounter;
use caliptra_dpe::commands::{
    CommandExecution, DeriveContextCmd, DeriveContextFlags, DestroyCtxCmd, SignFlags, SignP384Cmd,
};
use caliptra_dpe::context::ContextHandle;
use caliptra_dpe::dpe_instance::DpeInstance;
use caliptra_dpe::response::{Response, SignResp};
use caliptra_dpe::support::Support;
use caliptra_dpe::tci::TciMeasurement;
use caliptra_dpe::{DpeFlags, DpeProfile, State};

use helpers::dpe_harness::{self, LOCALITY};

/// Derive a child from the default context (consuming it) and return the child handle.
fn derive_from_default(
    dpe: &mut DpeInstance,
    env: &mut caliptra_dpe::dpe_instance::DpeEnv<impl caliptra_dpe::dpe_instance::DpeTypes>,
    measurement: [u8; 48],
) -> ContextHandle {
    let cmd = DeriveContextCmd {
        handle: ContextHandle::default(),
        data: TciMeasurement(measurement),
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

/// Execute a sign command and return (sig_r, sig_s, new_handle).
fn sign_p384(
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
        _ => panic!("Expected Sign P384 response, got unexpected response"),
    }
}

#[test]
fn sign_default_context_p384() {
    CfiCounter::reset_for_test();
    let (mut dpe, mut state) = dpe_harness::new_dpe_wolf(Support::AUTO_INIT);
    let mut env = dpe_harness::make_wolf_env(&mut state);

    let child = derive_from_default(&mut dpe, &mut env, [0x42; 48]);
    let (r, s, _) = sign_p384(&mut dpe, &mut env, child, [0xAA; 48], [0xBB; 48]);

    assert!(r.iter().any(|&b| b != 0), "sig_r should be non-zero");
    assert!(s.iter().any(|&b| b != 0), "sig_s should be non-zero");
}

#[test]
fn sign_produces_valid_length() {
    CfiCounter::reset_for_test();
    let (mut dpe, mut state) = dpe_harness::new_dpe_wolf(Support::AUTO_INIT);
    let mut env = dpe_harness::make_wolf_env(&mut state);

    let child = derive_from_default(&mut dpe, &mut env, [0x11; 48]);
    let (r, s, _) = sign_p384(&mut dpe, &mut env, child, [0; 48], [0xCC; 48]);

    // P-384 signature: r and s are each 48 bytes (384 bits), total 96 bytes.
    assert_eq!(r.len(), 48);
    assert_eq!(s.len(), 48);
    assert!(r.iter().any(|&b| b != 0), "r should be non-zero");
    assert!(s.iter().any(|&b| b != 0), "s should be non-zero");
}

#[test]
fn sign_with_measurement_affects_key() {
    CfiCounter::reset_for_test();

    // Instance A: derive with measurement A, sign.
    let (mut dpe_a, mut state_a) = dpe_harness::new_dpe_wolf(Support::AUTO_INIT);
    let mut env_a = dpe_harness::make_wolf_env(&mut state_a);
    let child_a = derive_from_default(&mut dpe_a, &mut env_a, [0xAA; 48]);
    let (r_a, s_a, _) = sign_p384(&mut dpe_a, &mut env_a, child_a, [0; 48], [0xDD; 48]);

    // Instance B: derive with measurement B, sign same digest.
    CfiCounter::reset_for_test();
    let (mut dpe_b, mut state_b) = dpe_harness::new_dpe_wolf(Support::AUTO_INIT);
    let mut env_b = dpe_harness::make_wolf_env(&mut state_b);
    let child_b = derive_from_default(&mut dpe_b, &mut env_b, [0xBB; 48]);
    let (r_b, s_b, _) = sign_p384(&mut dpe_b, &mut env_b, child_b, [0; 48], [0xDD; 48]);

    // Different measurements => different keys => different signatures.
    assert!(
        r_a != r_b || s_a != s_b,
        "Different measurements should produce different signatures"
    );
}

#[test]
fn sign_after_destroy_fails() {
    CfiCounter::reset_for_test();
    let (mut dpe, mut state) = dpe_harness::new_dpe_wolf(Support::AUTO_INIT);
    let mut env = dpe_harness::make_wolf_env(&mut state);

    let child = derive_from_default(&mut dpe, &mut env, [0x22; 48]);

    // Destroy the child context.
    let destroy = DestroyCtxCmd { handle: child };
    destroy.execute(&mut dpe, &mut env, LOCALITY).unwrap();

    // Sign with destroyed handle should fail.
    let sign_cmd = SignP384Cmd {
        handle: child,
        label: [0; 48],
        flags: SignFlags::empty(),
        digest: [0xFF; 48],
    };
    let result = sign_cmd.execute(&mut dpe, &mut env, LOCALITY);
    assert!(
        result.is_err(),
        "Expected error signing with destroyed handle"
    );
}

#[test]
fn sign_invalid_handle_fails() {
    CfiCounter::reset_for_test();
    let (mut dpe, mut state) = dpe_harness::new_dpe_wolf(Support::AUTO_INIT);
    let mut env = dpe_harness::make_wolf_env(&mut state);

    let bad_handle = ContextHandle([0xFF; 16]);
    let sign_cmd = SignP384Cmd {
        handle: bad_handle,
        label: [0; 48],
        flags: SignFlags::empty(),
        digest: [0xAA; 48],
    };
    let result = sign_cmd.execute(&mut dpe, &mut env, LOCALITY);
    assert!(
        result.is_err(),
        "Expected error signing with invalid handle"
    );
}

#[test]
fn sign_label_affects_key() {
    CfiCounter::reset_for_test();

    // Instance A: derive, sign with label_a.
    let (mut dpe_a, mut state_a) = dpe_harness::new_dpe_wolf(Support::AUTO_INIT);
    let mut env_a = dpe_harness::make_wolf_env(&mut state_a);
    let child_a = derive_from_default(&mut dpe_a, &mut env_a, [0x42; 48]);
    let (r_a, s_a, _) = sign_p384(&mut dpe_a, &mut env_a, child_a, [0xAA; 48], [0xDD; 48]);

    // Instance B: same measurement, sign with label_b.
    CfiCounter::reset_for_test();
    let (mut dpe_b, mut state_b) = dpe_harness::new_dpe_wolf(Support::AUTO_INIT);
    let mut env_b = dpe_harness::make_wolf_env(&mut state_b);
    let child_b = derive_from_default(&mut dpe_b, &mut env_b, [0x42; 48]);
    let (r_b, s_b, _) = sign_p384(&mut dpe_b, &mut env_b, child_b, [0xBB; 48], [0xDD; 48]);

    assert!(
        r_a != r_b || s_a != s_b,
        "Different labels should produce different signatures (different keys)"
    );
}

#[test]
fn sign_same_context_twice_succeeds() {
    CfiCounter::reset_for_test();

    // Sign twice with the same context. Both should succeed and produce valid signatures
    // (they may differ if the backend uses randomized ECDSA rather than RFC 6979).
    let (mut dpe, mut state) = dpe_harness::new_dpe_wolf(Support::AUTO_INIT);
    let mut env = dpe_harness::make_wolf_env(&mut state);
    let child = derive_from_default(&mut dpe, &mut env, [0x42; 48]);

    let (r_a, s_a, handle_after) = sign_p384(&mut dpe, &mut env, child, [0xAA; 48], [0xBB; 48]);
    assert!(
        r_a.iter().any(|&b| b != 0),
        "First sig_r should be non-zero"
    );
    assert!(
        s_a.iter().any(|&b| b != 0),
        "First sig_s should be non-zero"
    );

    let (r_b, s_b, _) = sign_p384(&mut dpe, &mut env, handle_after, [0xAA; 48], [0xBB; 48]);
    assert!(
        r_b.iter().any(|&b| b != 0),
        "Second sig_r should be non-zero"
    );
    assert!(
        s_b.iter().any(|&b| b != 0),
        "Second sig_s should be non-zero"
    );
}

#[test]
fn sign_different_digest_different_sig() {
    CfiCounter::reset_for_test();

    let (mut dpe_a, mut state_a) = dpe_harness::new_dpe_wolf(Support::AUTO_INIT);
    let mut env_a = dpe_harness::make_wolf_env(&mut state_a);
    let child_a = derive_from_default(&mut dpe_a, &mut env_a, [0x42; 48]);
    let (r_a, s_a, _) = sign_p384(&mut dpe_a, &mut env_a, child_a, [0xAA; 48], [0x11; 48]);

    CfiCounter::reset_for_test();
    let (mut dpe_b, mut state_b) = dpe_harness::new_dpe_wolf(Support::AUTO_INIT);
    let mut env_b = dpe_harness::make_wolf_env(&mut state_b);
    let child_b = derive_from_default(&mut dpe_b, &mut env_b, [0x42; 48]);
    let (r_b, s_b, _) = sign_p384(&mut dpe_b, &mut env_b, child_b, [0xAA; 48], [0x22; 48]);

    assert!(
        r_a != r_b || s_a != s_b,
        "Different digests should produce different signatures"
    );
}

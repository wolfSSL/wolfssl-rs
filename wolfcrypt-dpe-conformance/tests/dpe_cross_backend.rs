//! Cross-backend DPE tests: run the same DPE command sequences through wolf and
//! reference backends, then compare outputs. Both backends are deterministic for
//! the same inputs, so public keys and (deterministic) signatures must match.

mod helpers;

use caliptra_cfi_lib::CfiCounter;
use caliptra_dpe::commands::{
    CertifyKeyFlags, CertifyKeyP384Cmd, CommandExecution, DeriveContextCmd, DeriveContextFlags,
    GetProfileCmd, SignFlags, SignP384Cmd,
};
use caliptra_dpe::context::ContextHandle;
use caliptra_dpe::dpe_instance::DpeInstance;
use caliptra_dpe::response::{CertifyKeyResp, Response, SignResp};
use caliptra_dpe::tci::TciMeasurement;
use caliptra_dpe::{DpeProfile, State};
use caliptra_dpe_crypto::Crypto;

/// Extract (pubkey_x, pubkey_y) from a CertifyKey P384 response.
fn certify_pubkey(resp: Response) -> ([u8; 48], [u8; 48]) {
    match resp {
        Response::CertifyKey(CertifyKeyResp::P384(r)) => {
            (r.derived_pubkey_x, r.derived_pubkey_y)
        }
        _ => panic!("Expected CertifyKey P384 response"),
    }
}

/// Extract (sig_r, sig_s) from a Sign P384 response.
fn sign_rs(resp: Response) -> ([u8; 48], [u8; 48]) {
    match resp {
        Response::Sign(SignResp::P384(r)) => (r.sig_r, r.sig_s),
        _ => panic!("Expected Sign P384 response"),
    }
}

/// Set up the alias key on a wolf DpeEnv so CertifyKey can sign certificates.
/// Uses a deterministic key derived from a fixed measurement.
fn setup_wolf_alias(env: &mut caliptra_dpe::dpe_instance::DpeEnv<'_, helpers::dpe_harness::WolfDpeTypes384>) {
    let measurement = helpers::fixed_measurement_384(0xFF);
    let cdi = env.crypto.derive_cdi(&measurement, b"alias-setup").unwrap();
    let (priv_key, pub_key) = env.crypto.derive_key_pair(&cdi, b"alias-lbl", b"alias-inf").unwrap();
    env.crypto.set_alias_key(priv_key, pub_key).unwrap();
}

#[test]
fn init_same_profile() {
    CfiCounter::reset_for_test();
    let support = helpers::dpe_harness::DEFAULT_SUPPORT;

    let mut wolf_state = State::new(support, caliptra_dpe::DpeFlags::empty());
    let mut wolf_env = helpers::dpe_harness::make_wolf_env(&mut wolf_state);
    let mut wolf_dpe = DpeInstance::new(&mut wolf_env, DpeProfile::P384Sha384)
        .expect("Wolf DPE init should succeed");

    CfiCounter::reset_for_test();
    let mut ref_state = State::new(support, caliptra_dpe::DpeFlags::empty());
    let mut ref_env = helpers::dpe_harness::make_ref_env(&mut ref_state);
    let mut ref_dpe = DpeInstance::new(&mut ref_env, DpeProfile::P384Sha384)
        .expect("Ref DPE init should succeed");

    let wolf_profile = GetProfileCmd
        .execute(&mut wolf_dpe, &mut wolf_env, helpers::dpe_harness::LOCALITY)
        .expect("Wolf GetProfile should succeed");
    CfiCounter::reset_for_test();
    let ref_profile = GetProfileCmd
        .execute(&mut ref_dpe, &mut ref_env, helpers::dpe_harness::LOCALITY)
        .expect("Ref GetProfile should succeed");

    match (&wolf_profile, &ref_profile) {
        (Response::GetProfile(w), Response::GetProfile(r)) => {
            assert_eq!(
                w.flags, r.flags,
                "Wolf and ref GetProfile flags must match"
            );
            assert_eq!(
                w.max_tci_nodes, r.max_tci_nodes,
                "Wolf and ref max_tci_nodes must match"
            );
        }
        _ => panic!("Expected GetProfile responses from both backends"),
    }
}

#[test]
fn derive_same_key_from_same_measurement() {
    // CertifyKey requires alias key on wolf, so we set it up.
    // Both backends derive keys deterministically from the same measurement chain,
    // so the public keys must match.
    let support = helpers::dpe_harness::DEFAULT_SUPPORT;
    let measurement = TciMeasurement([0x42; 48]);
    let label = [0xBB; 48];

    // Wolf
    CfiCounter::reset_for_test();
    let wolf_pk = {
        let mut state = State::new(support, caliptra_dpe::DpeFlags::empty());
        let mut env = helpers::dpe_harness::make_wolf_env(&mut state);
        setup_wolf_alias(&mut env);
        let mut dpe = DpeInstance::new(&mut env, DpeProfile::P384Sha384).unwrap();

        let derive_cmd = DeriveContextCmd {
            handle: ContextHandle::default(),
            data: measurement,
            flags: DeriveContextFlags::MAKE_DEFAULT | DeriveContextFlags::INPUT_ALLOW_X509,
            tci_type: 0,
            target_locality: helpers::dpe_harness::LOCALITY,
            svn: 0,
        };
        derive_cmd
            .execute(&mut dpe, &mut env, helpers::dpe_harness::LOCALITY)
            .unwrap();

        let certify_cmd = CertifyKeyP384Cmd {
            handle: ContextHandle::default(),
            format: 0,
            label,
            flags: CertifyKeyFlags::empty(),
        };
        certify_pubkey(
            certify_cmd
                .execute(&mut dpe, &mut env, helpers::dpe_harness::LOCALITY)
                .unwrap(),
        )
    };

    // Reference
    CfiCounter::reset_for_test();
    let ref_pk = {
        let mut state = State::new(support, caliptra_dpe::DpeFlags::empty());
        let mut env = helpers::dpe_harness::make_ref_env(&mut state);
        let mut dpe = DpeInstance::new(&mut env, DpeProfile::P384Sha384).unwrap();

        let derive_cmd = DeriveContextCmd {
            handle: ContextHandle::default(),
            data: measurement,
            flags: DeriveContextFlags::MAKE_DEFAULT | DeriveContextFlags::INPUT_ALLOW_X509,
            tci_type: 0,
            target_locality: helpers::dpe_harness::LOCALITY,
            svn: 0,
        };
        derive_cmd
            .execute(&mut dpe, &mut env, helpers::dpe_harness::LOCALITY)
            .unwrap();

        let certify_cmd = CertifyKeyP384Cmd {
            handle: ContextHandle::default(),
            format: 0,
            label,
            flags: CertifyKeyFlags::empty(),
        };
        certify_pubkey(
            certify_cmd
                .execute(&mut dpe, &mut env, helpers::dpe_harness::LOCALITY)
                .unwrap(),
        )
    };

    assert_eq!(
        wolf_pk.0, ref_pk.0,
        "Wolf and ref must produce same pubkey X from same measurement"
    );
    assert_eq!(
        wolf_pk.1, ref_pk.1,
        "Wolf and ref must produce same pubkey Y from same measurement"
    );
}

#[test]
fn sign_same_digest_both_valid() {
    // ECDSA is not necessarily deterministic (different random k), so we verify
    // that both backends produce valid signatures for the same derived key.
    // We derive the same key on both sides and cross-verify each signature
    // using an independent P-384 verifier.
    let support = helpers::dpe_harness::DEFAULT_SUPPORT;
    let measurement = TciMeasurement([0x55; 48]);
    let label = [0xCC; 48];
    let digest = [0xDD; 48];

    // Wolf: derive + sign + certify (for pubkey)
    CfiCounter::reset_for_test();
    let (wolf_sig, wolf_pk) = {
        let mut state = State::new(support, caliptra_dpe::DpeFlags::empty());
        let mut env = helpers::dpe_harness::make_wolf_env(&mut state);
        setup_wolf_alias(&mut env);
        let mut dpe = DpeInstance::new(&mut env, DpeProfile::P384Sha384).unwrap();

        let derive_cmd = DeriveContextCmd {
            handle: ContextHandle::default(),
            data: measurement,
            flags: DeriveContextFlags::MAKE_DEFAULT | DeriveContextFlags::INPUT_ALLOW_X509,
            tci_type: 0,
            target_locality: helpers::dpe_harness::LOCALITY,
            svn: 0,
        };
        derive_cmd
            .execute(&mut dpe, &mut env, helpers::dpe_harness::LOCALITY)
            .unwrap();

        let sign_cmd = SignP384Cmd {
            handle: ContextHandle::default(),
            label,
            flags: SignFlags::empty(),
            digest,
        };
        let sig = sign_rs(
            sign_cmd
                .execute(&mut dpe, &mut env, helpers::dpe_harness::LOCALITY)
                .unwrap(),
        );

        // CertifyKey to get public key
        let certify_cmd = CertifyKeyP384Cmd {
            handle: ContextHandle::default(),
            format: 0,
            label,
            flags: CertifyKeyFlags::empty(),
        };
        let pk = certify_pubkey(
            certify_cmd
                .execute(&mut dpe, &mut env, helpers::dpe_harness::LOCALITY)
                .unwrap(),
        );
        (sig, pk)
    };

    // Reference: derive + sign + certify (for pubkey)
    CfiCounter::reset_for_test();
    let (ref_sig, ref_pk) = {
        let mut state = State::new(support, caliptra_dpe::DpeFlags::empty());
        let mut env = helpers::dpe_harness::make_ref_env(&mut state);
        let mut dpe = DpeInstance::new(&mut env, DpeProfile::P384Sha384).unwrap();

        let derive_cmd = DeriveContextCmd {
            handle: ContextHandle::default(),
            data: measurement,
            flags: DeriveContextFlags::MAKE_DEFAULT | DeriveContextFlags::INPUT_ALLOW_X509,
            tci_type: 0,
            target_locality: helpers::dpe_harness::LOCALITY,
            svn: 0,
        };
        derive_cmd
            .execute(&mut dpe, &mut env, helpers::dpe_harness::LOCALITY)
            .unwrap();

        let sign_cmd = SignP384Cmd {
            handle: ContextHandle::default(),
            label,
            flags: SignFlags::empty(),
            digest,
        };
        let sig = sign_rs(
            sign_cmd
                .execute(&mut dpe, &mut env, helpers::dpe_harness::LOCALITY)
                .unwrap(),
        );

        let certify_cmd = CertifyKeyP384Cmd {
            handle: ContextHandle::default(),
            format: 0,
            label,
            flags: CertifyKeyFlags::empty(),
        };
        let pk = certify_pubkey(
            certify_cmd
                .execute(&mut dpe, &mut env, helpers::dpe_harness::LOCALITY)
                .unwrap(),
        );
        (sig, pk)
    };

    // Public keys must match (deterministic key derivation)
    assert_eq!(
        wolf_pk.0, ref_pk.0,
        "Wolf and ref must derive same pubkey X"
    );
    assert_eq!(
        wolf_pk.1, ref_pk.1,
        "Wolf and ref must derive same pubkey Y"
    );

    // Build SEC1 uncompressed pubkey for verification
    let mut pk_sec1 = Vec::with_capacity(97);
    pk_sec1.push(0x04);
    pk_sec1.extend_from_slice(&wolf_pk.0);
    pk_sec1.extend_from_slice(&wolf_pk.1);

    // Build r||s for each signature
    let mut wolf_sig_bytes = Vec::with_capacity(96);
    wolf_sig_bytes.extend_from_slice(&wolf_sig.0);
    wolf_sig_bytes.extend_from_slice(&wolf_sig.1);

    let mut ref_sig_bytes = Vec::with_capacity(96);
    ref_sig_bytes.extend_from_slice(&ref_sig.0);
    ref_sig_bytes.extend_from_slice(&ref_sig.1);

    // Both signatures must independently verify against the shared pubkey
    helpers::verify_p384_signature(&pk_sec1, &digest, &wolf_sig_bytes)
        .expect("Wolf signature must verify against shared pubkey");
    helpers::verify_p384_signature(&pk_sec1, &digest, &ref_sig_bytes)
        .expect("Ref signature must verify against shared pubkey");
}

#[test]
fn certify_same_pubkey() {
    let support = helpers::dpe_harness::DEFAULT_SUPPORT;
    let measurement = TciMeasurement([0x77; 48]);
    let label = [0x11; 48];

    // Wolf (with alias key setup)
    CfiCounter::reset_for_test();
    let wolf_pk = {
        let mut state = State::new(support, caliptra_dpe::DpeFlags::empty());
        let mut env = helpers::dpe_harness::make_wolf_env(&mut state);
        setup_wolf_alias(&mut env);
        let mut dpe = DpeInstance::new(&mut env, DpeProfile::P384Sha384).unwrap();

        let derive_cmd = DeriveContextCmd {
            handle: ContextHandle::default(),
            data: measurement,
            flags: DeriveContextFlags::MAKE_DEFAULT | DeriveContextFlags::INPUT_ALLOW_X509,
            tci_type: 0,
            target_locality: helpers::dpe_harness::LOCALITY,
            svn: 0,
        };
        derive_cmd
            .execute(&mut dpe, &mut env, helpers::dpe_harness::LOCALITY)
            .unwrap();

        let certify_cmd = CertifyKeyP384Cmd {
            handle: ContextHandle::default(),
            format: 0,
            label,
            flags: CertifyKeyFlags::empty(),
        };
        certify_pubkey(
            certify_cmd
                .execute(&mut dpe, &mut env, helpers::dpe_harness::LOCALITY)
                .unwrap(),
        )
    };

    // Reference
    CfiCounter::reset_for_test();
    let ref_pk = {
        let mut state = State::new(support, caliptra_dpe::DpeFlags::empty());
        let mut env = helpers::dpe_harness::make_ref_env(&mut state);
        let mut dpe = DpeInstance::new(&mut env, DpeProfile::P384Sha384).unwrap();

        let derive_cmd = DeriveContextCmd {
            handle: ContextHandle::default(),
            data: measurement,
            flags: DeriveContextFlags::MAKE_DEFAULT | DeriveContextFlags::INPUT_ALLOW_X509,
            tci_type: 0,
            target_locality: helpers::dpe_harness::LOCALITY,
            svn: 0,
        };
        derive_cmd
            .execute(&mut dpe, &mut env, helpers::dpe_harness::LOCALITY)
            .unwrap();

        let certify_cmd = CertifyKeyP384Cmd {
            handle: ContextHandle::default(),
            format: 0,
            label,
            flags: CertifyKeyFlags::empty(),
        };
        certify_pubkey(
            certify_cmd
                .execute(&mut dpe, &mut env, helpers::dpe_harness::LOCALITY)
                .unwrap(),
        )
    };

    assert_eq!(
        wolf_pk.0, ref_pk.0,
        "Wolf and ref CertifyKey pubkey X must match"
    );
    assert_eq!(
        wolf_pk.1, ref_pk.1,
        "Wolf and ref CertifyKey pubkey Y must match"
    );
}

#[test]
fn full_pipeline_cross() {
    let support = helpers::dpe_harness::FULL_SUPPORT;
    let meas_1 = TciMeasurement([0x11; 48]);
    let meas_2 = TciMeasurement([0x22; 48]);
    let label = [0xEE; 48];

    // Wolf pipeline: init -> derive(meas_1) -> derive(meas_2, RECURSIVE) -> certify
    CfiCounter::reset_for_test();
    let wolf_pk = {
        let mut state = State::new(support, caliptra_dpe::DpeFlags::empty());
        let mut env = helpers::dpe_harness::make_wolf_env(&mut state);
        setup_wolf_alias(&mut env);
        let mut dpe = DpeInstance::new(&mut env, DpeProfile::P384Sha384).unwrap();

        let derive1 = DeriveContextCmd {
            handle: ContextHandle::default(),
            data: meas_1,
            flags: DeriveContextFlags::MAKE_DEFAULT | DeriveContextFlags::INPUT_ALLOW_X509,
            tci_type: 0,
            target_locality: helpers::dpe_harness::LOCALITY,
            svn: 0,
        };
        derive1
            .execute(&mut dpe, &mut env, helpers::dpe_harness::LOCALITY)
            .unwrap();

        let derive2 = DeriveContextCmd {
            handle: ContextHandle::default(),
            data: meas_2,
            flags: DeriveContextFlags::MAKE_DEFAULT
                | DeriveContextFlags::RECURSIVE
                | DeriveContextFlags::INPUT_ALLOW_X509,
            tci_type: 0,
            target_locality: helpers::dpe_harness::LOCALITY,
            svn: 0,
        };
        derive2
            .execute(&mut dpe, &mut env, helpers::dpe_harness::LOCALITY)
            .unwrap();

        let certify_cmd = CertifyKeyP384Cmd {
            handle: ContextHandle::default(),
            format: 0,
            label,
            flags: CertifyKeyFlags::empty(),
        };
        certify_pubkey(
            certify_cmd
                .execute(&mut dpe, &mut env, helpers::dpe_harness::LOCALITY)
                .unwrap(),
        )
    };

    // Ref pipeline: same sequence
    CfiCounter::reset_for_test();
    let ref_pk = {
        let mut state = State::new(support, caliptra_dpe::DpeFlags::empty());
        let mut env = helpers::dpe_harness::make_ref_env(&mut state);
        let mut dpe = DpeInstance::new(&mut env, DpeProfile::P384Sha384).unwrap();

        let derive1 = DeriveContextCmd {
            handle: ContextHandle::default(),
            data: meas_1,
            flags: DeriveContextFlags::MAKE_DEFAULT | DeriveContextFlags::INPUT_ALLOW_X509,
            tci_type: 0,
            target_locality: helpers::dpe_harness::LOCALITY,
            svn: 0,
        };
        derive1
            .execute(&mut dpe, &mut env, helpers::dpe_harness::LOCALITY)
            .unwrap();

        let derive2 = DeriveContextCmd {
            handle: ContextHandle::default(),
            data: meas_2,
            flags: DeriveContextFlags::MAKE_DEFAULT
                | DeriveContextFlags::RECURSIVE
                | DeriveContextFlags::INPUT_ALLOW_X509,
            tci_type: 0,
            target_locality: helpers::dpe_harness::LOCALITY,
            svn: 0,
        };
        derive2
            .execute(&mut dpe, &mut env, helpers::dpe_harness::LOCALITY)
            .unwrap();

        let certify_cmd = CertifyKeyP384Cmd {
            handle: ContextHandle::default(),
            format: 0,
            label,
            flags: CertifyKeyFlags::empty(),
        };
        certify_pubkey(
            certify_cmd
                .execute(&mut dpe, &mut env, helpers::dpe_harness::LOCALITY)
                .unwrap(),
        )
    };

    assert_eq!(
        wolf_pk.0, ref_pk.0,
        "Full pipeline: wolf and ref pubkey X must match"
    );
    assert_eq!(
        wolf_pk.1, ref_pk.1,
        "Full pipeline: wolf and ref pubkey Y must match"
    );
}

#[test]
fn measurement_chain_deterministic() {
    let support = helpers::dpe_harness::FULL_SUPPORT;
    let measurements = [
        TciMeasurement([0x10; 48]),
        TciMeasurement([0x20; 48]),
        TciMeasurement([0x30; 48]),
    ];
    let label = [0xFF; 48];

    // Wolf
    CfiCounter::reset_for_test();
    let wolf_pk = {
        let mut state = State::new(support, caliptra_dpe::DpeFlags::empty());
        let mut env = helpers::dpe_harness::make_wolf_env(&mut state);
        setup_wolf_alias(&mut env);
        let mut dpe = DpeInstance::new(&mut env, DpeProfile::P384Sha384).unwrap();

        let derive1 = DeriveContextCmd {
            handle: ContextHandle::default(),
            data: measurements[0],
            flags: DeriveContextFlags::MAKE_DEFAULT | DeriveContextFlags::INPUT_ALLOW_X509,
            tci_type: 0,
            target_locality: helpers::dpe_harness::LOCALITY,
            svn: 0,
        };
        derive1
            .execute(&mut dpe, &mut env, helpers::dpe_harness::LOCALITY)
            .unwrap();

        for m in &measurements[1..] {
            let derive = DeriveContextCmd {
                handle: ContextHandle::default(),
                data: *m,
                flags: DeriveContextFlags::MAKE_DEFAULT
                    | DeriveContextFlags::RECURSIVE
                    | DeriveContextFlags::INPUT_ALLOW_X509,
                tci_type: 0,
                target_locality: helpers::dpe_harness::LOCALITY,
                svn: 0,
            };
            derive
                .execute(&mut dpe, &mut env, helpers::dpe_harness::LOCALITY)
                .unwrap();
        }

        let certify = CertifyKeyP384Cmd {
            handle: ContextHandle::default(),
            format: 0,
            label,
            flags: CertifyKeyFlags::empty(),
        };
        certify_pubkey(
            certify
                .execute(&mut dpe, &mut env, helpers::dpe_harness::LOCALITY)
                .unwrap(),
        )
    };

    // Reference
    CfiCounter::reset_for_test();
    let ref_pk = {
        let mut state = State::new(support, caliptra_dpe::DpeFlags::empty());
        let mut env = helpers::dpe_harness::make_ref_env(&mut state);
        let mut dpe = DpeInstance::new(&mut env, DpeProfile::P384Sha384).unwrap();

        let derive1 = DeriveContextCmd {
            handle: ContextHandle::default(),
            data: measurements[0],
            flags: DeriveContextFlags::MAKE_DEFAULT | DeriveContextFlags::INPUT_ALLOW_X509,
            tci_type: 0,
            target_locality: helpers::dpe_harness::LOCALITY,
            svn: 0,
        };
        derive1
            .execute(&mut dpe, &mut env, helpers::dpe_harness::LOCALITY)
            .unwrap();

        for m in &measurements[1..] {
            let derive = DeriveContextCmd {
                handle: ContextHandle::default(),
                data: *m,
                flags: DeriveContextFlags::MAKE_DEFAULT
                    | DeriveContextFlags::RECURSIVE
                    | DeriveContextFlags::INPUT_ALLOW_X509,
                tci_type: 0,
                target_locality: helpers::dpe_harness::LOCALITY,
                svn: 0,
            };
            derive
                .execute(&mut dpe, &mut env, helpers::dpe_harness::LOCALITY)
                .unwrap();
        }

        let certify = CertifyKeyP384Cmd {
            handle: ContextHandle::default(),
            format: 0,
            label,
            flags: CertifyKeyFlags::empty(),
        };
        certify_pubkey(
            certify
                .execute(&mut dpe, &mut env, helpers::dpe_harness::LOCALITY)
                .unwrap(),
        )
    };

    assert_eq!(
        wolf_pk.0, ref_pk.0,
        "3-measurement chain: wolf and ref pubkey X must match"
    );
    assert_eq!(
        wolf_pk.1, ref_pk.1,
        "3-measurement chain: wolf and ref pubkey Y must match"
    );
}

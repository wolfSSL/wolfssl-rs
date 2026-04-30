//! Meta-tests ("canary" tests) that verify the test harness itself detects
//! failures. If these pass, we can trust that the conformance assertions in
//! other modules are meaningful.

mod helpers;

use caliptra_cfi_lib::CfiCounter;
use caliptra_dpe::commands::{
    CertifyKeyFlags, CertifyKeyP384Cmd, CommandExecution, DeriveContextCmd, DeriveContextFlags,
    SignFlags, SignP384Cmd,
};
use caliptra_dpe::context::ContextHandle;
use caliptra_dpe::dpe_instance::DpeInstance;
use caliptra_dpe::response::{CertifyKeyResp, Response};
use caliptra_dpe::tci::TciMeasurement;
use caliptra_dpe::{DpeProfile, State};
use caliptra_dpe_crypto::Crypto;

/// Set up the alias key on a wolf DpeEnv so CertifyKey can sign certificates.
fn setup_wolf_alias(
    env: &mut caliptra_dpe::dpe_instance::DpeEnv<'_, helpers::dpe_harness::WolfDpeTypes384>,
) {
    let measurement = helpers::fixed_measurement_384(0xFF);
    let cdi = env.crypto.derive_cdi(&measurement, b"alias-setup").unwrap();
    let (priv_key, pub_key) = env
        .crypto
        .derive_key_pair(&cdi, b"alias-lbl", b"alias-inf")
        .unwrap();
    env.crypto.set_alias_key(priv_key, pub_key).unwrap();
}

#[test]
fn hash_comparison_works() {
    CfiCounter::reset_for_test();
    let mut wolf = helpers::new_wolf_384();
    let hash_a = wolf.hash(b"A").expect("hash A should succeed");
    let hash_b = wolf.hash(b"B").expect("hash B should succeed");
    assert_ne!(
        hash_a.as_slice(),
        hash_b.as_slice(),
        "Hash of 'A' and 'B' must differ"
    );
}

#[test]
fn cdi_comparison_works() {
    CfiCounter::reset_for_test();
    let mut wolf = helpers::new_wolf_384();
    let meas_a = helpers::fixed_measurement_384(0xAA);
    let meas_b = helpers::fixed_measurement_384(0xBB);
    let cdi_a = wolf
        .derive_cdi(&meas_a, b"canary")
        .expect("derive_cdi A should succeed");
    let cdi_b = wolf
        .derive_cdi(&meas_b, b"canary")
        .expect("derive_cdi B should succeed");
    assert_ne!(
        cdi_a.as_slice(),
        cdi_b.as_slice(),
        "CDIs from different measurements must differ"
    );
}

#[test]
fn keypair_comparison_works() {
    CfiCounter::reset_for_test();
    let mut wolf = helpers::new_wolf_384();
    let meas_a = helpers::fixed_measurement_384(0x01);
    let meas_b = helpers::fixed_measurement_384(0x02);
    let cdi_a = wolf.derive_cdi(&meas_a, b"keypair").unwrap();
    let cdi_b = wolf.derive_cdi(&meas_b, b"keypair").unwrap();
    let (_, pub_a) = wolf
        .derive_key_pair(&cdi_a, b"label", b"info")
        .expect("derive_key_pair A should succeed");
    let (_, pub_b) = wolf
        .derive_key_pair(&cdi_b, b"label", b"info")
        .expect("derive_key_pair B should succeed");
    let pk_a = helpers::pubkey_to_uncompressed(&pub_a);
    let pk_b = helpers::pubkey_to_uncompressed(&pub_b);
    assert_ne!(pk_a, pk_b, "Public keys from different CDIs must differ");
}

#[test]
fn signature_not_message() {
    CfiCounter::reset_for_test();
    let support = helpers::dpe_harness::DEFAULT_SUPPORT;
    let mut state = State::new(support, caliptra_dpe::DpeFlags::empty());
    let mut env = helpers::dpe_harness::make_wolf_env(&mut state);
    let mut dpe =
        DpeInstance::new(&mut env, DpeProfile::P384Sha384).expect("DPE init should succeed");

    let derive_cmd = DeriveContextCmd {
        handle: ContextHandle::default(),
        data: TciMeasurement([0x42; 48]),
        flags: DeriveContextFlags::MAKE_DEFAULT,
        tci_type: 0,
        target_locality: helpers::dpe_harness::LOCALITY,
        svn: 0,
    };
    derive_cmd
        .execute(&mut dpe, &mut env, helpers::dpe_harness::LOCALITY)
        .unwrap();

    let digest = [0xDD; 48];
    let sign_cmd = SignP384Cmd {
        handle: ContextHandle::default(),
        label: [0xAA; 48],
        flags: SignFlags::empty(),
        digest,
    };
    let resp = sign_cmd
        .execute(&mut dpe, &mut env, helpers::dpe_harness::LOCALITY)
        .expect("Sign should succeed");

    match resp {
        Response::Sign(caliptra_dpe::response::SignResp::P384(r)) => {
            let sig_bytes: Vec<u8> = r.sig_r.iter().chain(r.sig_s.iter()).copied().collect();
            assert_ne!(
                &sig_bytes[..48],
                &digest[..],
                "Signature R must not be identical to the digest"
            );
        }
        _ => panic!("Expected Sign P384 response"),
    }
}

#[test]
fn sign_with_alias_requires_setup() {
    CfiCounter::reset_for_test();
    let mut wolf = helpers::new_wolf_384();
    let measurement = helpers::fixed_measurement_384(0xAA);
    let sign_data = caliptra_dpe_crypto::SignData::Digest(measurement);
    let result = wolf.sign_with_alias(&sign_data);
    assert!(
        result.is_err(),
        "sign_with_alias should fail when alias key has not been set"
    );
}

#[test]
fn dpe_init_required() {
    // Create DPE without AUTO_INIT. The default handle should not work for Sign.
    CfiCounter::reset_for_test();
    let support =
        helpers::dpe_harness::DEFAULT_SUPPORT.difference(caliptra_dpe::support::Support::AUTO_INIT);
    let mut state = State::new(support, caliptra_dpe::DpeFlags::empty());
    let mut env = helpers::dpe_harness::make_wolf_env(&mut state);
    let mut dpe =
        DpeInstance::new(&mut env, DpeProfile::P384Sha384).expect("DPE init should succeed");

    let sign_cmd = SignP384Cmd {
        handle: ContextHandle::default(),
        label: [0x00; 48],
        flags: SignFlags::empty(),
        digest: [0x11; 48],
    };
    let result = sign_cmd.execute(&mut dpe, &mut env, helpers::dpe_harness::LOCALITY);
    assert!(
        result.is_err(),
        "Sign with default handle should fail when DPE is not AUTO_INIT'd"
    );
}

#[test]
fn wrong_handle_detected() {
    CfiCounter::reset_for_test();
    let support = helpers::dpe_harness::DEFAULT_SUPPORT;
    let mut state = State::new(support, caliptra_dpe::DpeFlags::empty());
    let mut env = helpers::dpe_harness::make_wolf_env(&mut state);
    let mut dpe =
        DpeInstance::new(&mut env, DpeProfile::P384Sha384).expect("DPE init should succeed");

    let bad_handle = ContextHandle([0xDE; 16]);
    let sign_cmd = SignP384Cmd {
        handle: bad_handle,
        label: [0x00; 48],
        flags: SignFlags::empty(),
        digest: [0x11; 48],
    };
    let result = sign_cmd.execute(&mut dpe, &mut env, helpers::dpe_harness::LOCALITY);
    assert!(
        result.is_err(),
        "Sign with a random/invalid handle must fail"
    );
}

#[test]
fn cert_parse_detects_garbage() {
    CfiCounter::reset_for_test();
    let garbage = [0xFF; 100];
    let result = helpers::x509_parser::parse_cert(&garbage);
    assert!(
        result.is_err(),
        "parse_cert must return Err for garbage input, not Ok"
    );
}

#[test]
fn cross_backend_different_inputs_differ() {
    let support = helpers::dpe_harness::DEFAULT_SUPPORT;

    // Wolf: measurement A (with alias key setup for CertifyKey)
    CfiCounter::reset_for_test();
    let wolf_pk = {
        let mut state = State::new(support, caliptra_dpe::DpeFlags::empty());
        let mut env = helpers::dpe_harness::make_wolf_env(&mut state);
        setup_wolf_alias(&mut env);
        let mut dpe = DpeInstance::new(&mut env, DpeProfile::P384Sha384).unwrap();

        let derive_cmd = DeriveContextCmd {
            handle: ContextHandle::default(),
            data: TciMeasurement([0xAA; 48]),
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
            label: [0xEE; 48],
            flags: CertifyKeyFlags::empty(),
        };
        match certify_cmd
            .execute(&mut dpe, &mut env, helpers::dpe_harness::LOCALITY)
            .unwrap()
        {
            Response::CertifyKey(CertifyKeyResp::P384(r)) => {
                (r.derived_pubkey_x, r.derived_pubkey_y)
            }
            _ => panic!("Expected CertifyKey P384"),
        }
    };

    // Ref: measurement B (different)
    CfiCounter::reset_for_test();
    let ref_pk = {
        let mut state = State::new(support, caliptra_dpe::DpeFlags::empty());
        let mut env = helpers::dpe_harness::make_ref_env(&mut state);
        let mut dpe = DpeInstance::new(&mut env, DpeProfile::P384Sha384).unwrap();

        let derive_cmd = DeriveContextCmd {
            handle: ContextHandle::default(),
            data: TciMeasurement([0xBB; 48]),
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
            label: [0xEE; 48],
            flags: CertifyKeyFlags::empty(),
        };
        match certify_cmd
            .execute(&mut dpe, &mut env, helpers::dpe_harness::LOCALITY)
            .unwrap()
        {
            Response::CertifyKey(CertifyKeyResp::P384(r)) => {
                (r.derived_pubkey_x, r.derived_pubkey_y)
            }
            _ => panic!("Expected CertifyKey P384"),
        }
    };

    assert!(
        wolf_pk.0 != ref_pk.0 || wolf_pk.1 != ref_pk.1,
        "Wolf(meas_A) and Ref(meas_B) must produce different public keys"
    );
}

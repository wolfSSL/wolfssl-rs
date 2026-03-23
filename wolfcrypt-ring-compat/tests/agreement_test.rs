// Copyright 2015-2016 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright wolfSSL Inc.
// SPDX-License-Identifier: MIT

use ring::{agreement, error, rand, test, test_file};

fn alg_from_curve_name(curve_name: &str) -> &'static agreement::Algorithm {
    match curve_name {
        "P-256" => &agreement::ECDH_P256,
        "P-384" => &agreement::ECDH_P384,
        "P-521" => &agreement::ECDH_P521,
        "X25519" => &agreement::X25519,
        _ => panic!("Unsupported curve: {curve_name}"),
    }
}

#[test]
fn agreement_agree() {
    let rng = rand::SystemRandom::new();

    test::run(
        test_file!("data/agreement_tests.txt"),
        |_section, test_case| {
            let curve_name = test_case.consume_string("Curve");
            let alg = alg_from_curve_name(&curve_name);
            let peer_public_key_bytes = test_case.consume_bytes("PeerQ");

            match test_case.consume_optional_string("Error") {
                None => {
                    let my_private_bytes = test_case.consume_bytes("D");
                    let _my_public_bytes = test_case.consume_bytes("MyQ");
                    let _my_q_format = test_case.consume_optional_string("MyQFormat");
                    let expected_output = test_case.consume_bytes("Output");

                    let private_key =
                        agreement::PrivateKey::from_private_key(alg, &my_private_bytes)
                            .map_err(|_| error::Unspecified)?;

                    let computed_public = private_key.compute_public_key()?;
                    assert!(!computed_public.as_ref().is_empty());

                    let peer_public =
                        agreement::UnparsedPublicKey::new(alg, &peer_public_key_bytes);

                    let result = agreement::agree(
                        &private_key,
                        &peer_public,
                        error::Unspecified,
                        |key_material| Ok(Vec::from(key_material)),
                    )?;

                    assert_eq!(
                        expected_output, result,
                        "Agreement output mismatch for curve {curve_name}"
                    );
                }
                Some(_error_msg) => {
                    // For error cases, try agree with a valid private key and the
                    // invalid peer public key. Should fail.
                    let private_key =
                        agreement::EphemeralPrivateKey::generate(alg, &rng)?;
                    let peer_public =
                        agreement::UnparsedPublicKey::new(alg, &peer_public_key_bytes);

                    let result = agreement::agree_ephemeral(
                        private_key,
                        &peer_public,
                        error::Unspecified,
                        |_| Ok(()),
                    );
                    assert!(
                        result.is_err(),
                        "Expected error for invalid peer public key on curve {curve_name}"
                    );
                }
            }

            Ok(())
        },
    );
}

#[test]
fn agreement_ephemeral_generate_and_agree() {
    let rng = rand::SystemRandom::new();

    for alg in &[
        &agreement::ECDH_P256,
        &agreement::ECDH_P384,
        &agreement::ECDH_P521,
        &agreement::X25519,
    ] {
        let my_private = agreement::EphemeralPrivateKey::generate(alg, &rng).unwrap();
        let peer_private = agreement::EphemeralPrivateKey::generate(alg, &rng).unwrap();

        let my_public = my_private.compute_public_key().unwrap();
        let peer_public = peer_private.compute_public_key().unwrap();

        // Agree in both directions — shared secrets must match (DH commutativity)
        let my_shared = agreement::agree_ephemeral(
            my_private,
            &agreement::UnparsedPublicKey::new(alg, peer_public.as_ref()),
            error::Unspecified,
            |km| Ok(Vec::from(km)),
        )
        .unwrap();

        let peer_shared = agreement::agree_ephemeral(
            peer_private,
            &agreement::UnparsedPublicKey::new(alg, my_public.as_ref()),
            error::Unspecified,
            |km| Ok(Vec::from(km)),
        )
        .unwrap();

        assert_eq!(
            my_shared, peer_shared,
            "Shared secrets should match for {:?}",
            alg
        );
        assert!(
            !my_shared.is_empty(),
            "Shared secret should not be empty for {:?}",
            alg
        );
    }
}

#[test]
fn agreement_traits() {
    let rng = rand::SystemRandom::new();

    let ephemeral_private_key =
        agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng).unwrap();

    // EphemeralPrivateKey: Debug
    let _ = format!("{:?}", &ephemeral_private_key);

    let public_key = ephemeral_private_key.compute_public_key().unwrap();

    // PublicKey: AsRef<[u8]>, Clone, Debug
    let _ = public_key.as_ref();
    let _ = public_key.clone();
    let _ = format!("{:?}", &public_key);

    fn require_send<T: Send>(_: &T) {}
    fn require_sync<T: Sync>(_: &T) {}

    let unparsed = agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, public_key.as_ref());
    let _ = format!("{:?}", &unparsed);
    require_sync(&unparsed);

    // Algorithm: Debug, Eq, PartialEq
    assert_eq!(&agreement::ECDH_P256, &agreement::ECDH_P256);
    assert_ne!(&agreement::ECDH_P256, &agreement::ECDH_P384);
    let _ = format!("{:?}", &agreement::ECDH_P256);

    require_send(&public_key);
}

#[test]
fn agreement_different_keys_different_secrets() {
    let rng = rand::SystemRandom::new();

    let peer_private =
        agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng).unwrap();
    let peer_public = peer_private.compute_public_key().unwrap();

    let priv1 = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng).unwrap();
    let priv2 = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng).unwrap();

    let secret1 = agreement::agree_ephemeral(
        priv1,
        &agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, peer_public.as_ref()),
        error::Unspecified,
        |km| Ok(Vec::from(km)),
    )
    .unwrap();

    let secret2 = agreement::agree_ephemeral(
        priv2,
        &agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, peer_public.as_ref()),
        error::Unspecified,
        |km| Ok(Vec::from(km)),
    )
    .unwrap();

    assert_ne!(
        secret1, secret2,
        "Different private keys should produce different shared secrets"
    );
}

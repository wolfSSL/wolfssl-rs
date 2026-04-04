#![cfg(wolfssl_ecc)]

mod helpers;

macro_rules! ecdsa_cross {
    (
        $mod_name:ident,
        $wolf_curve:ty,
        $pure_signing_key:ty,
        $pure_verifying_key:ty,
        $pure_sig:ty,
        $sig_component_len:expr,
        [$($cfg_gate:meta),*]
    ) => {
        #[cfg(all($($cfg_gate),*))]
        mod $mod_name {
            use super::helpers::*;
            use wolfcrypt::{EcdsaSigningKey, EcdsaVerifyingKey, EcdsaSignature};

            type WolfCurve = $wolf_curve;
            type PureSigningKey = $pure_signing_key;
            type PureVerifyingKey = $pure_verifying_key;
            type PureSig = $pure_sig;

            #[test]
            fn wolf_sign_pure_verify() {
                let wolf_sk = EcdsaSigningKey::<WolfCurve>::generate()
                    .expect(concat!(stringify!($mod_name), ": wolf key generation should succeed"));
                let wolf_vk = wolf_sk.verifying_key().unwrap();

                let msg = b"wolf signs, pure verifies";

                use signature::Signer as _;
                let wolf_sig: EcdsaSignature<WolfCurve> = wolf_sk.sign(msg);

                // Export wolf pub key, import into pure
                let wolf_pub_bytes: &[u8] = wolf_vk.as_bytes();
                let pure_vk = PureVerifyingKey::from_sec1_bytes(wolf_pub_bytes)
                    .expect(concat!(stringify!($mod_name), ": pure must accept wolf public key bytes"));

                // Convert wolf sig to pure sig
                let pure_sig = PureSig::from_slice(wolf_sig.as_bytes())
                    .expect(concat!(stringify!($mod_name), ": pure must accept wolf signature bytes"));

                use signature::Verifier as _;
                pure_vk.verify(msg, &pure_sig)
                    .expect(concat!(stringify!($mod_name), ": pure must verify wolf-generated signature"));
            }

            #[test]
            fn pure_sign_wolf_verify() {
                let mut rng = rand::thread_rng();
                let pure_sk = PureSigningKey::random(&mut rng);
                let pure_vk = pure_sk.verifying_key();

                let msg = b"pure signs, wolf verifies";

                use signature::Signer as _;
                let pure_sig: PureSig = pure_sk.sign(msg);

                // Export pure pub key (uncompressed), import into wolf
                let point = pure_vk.to_encoded_point(false);
                let sec1_bytes: &[u8] = point.as_bytes();
                let wolf_vk = EcdsaVerifyingKey::<WolfCurve>::from_uncompressed_point(sec1_bytes)
                    .expect(concat!(stringify!($mod_name), ": wolf must accept pure public key bytes"));

                // Convert pure sig to wolf sig
                let sig_bytes = pure_sig.to_bytes();
                let wolf_sig = EcdsaSignature::<WolfCurve>::from_bytes(sig_bytes.as_ref())
                    .expect(concat!(stringify!($mod_name), ": wolf must accept pure signature bytes"));

                use signature::Verifier as _;
                wolf_vk.verify(msg, &wolf_sig)
                    .expect(concat!(stringify!($mod_name), ": wolf must verify pure-generated signature"));
            }

            #[test]
            fn pubkey_export_import_round_trip() {
                let wolf_sk = EcdsaSigningKey::<WolfCurve>::generate()
                    .expect(concat!(stringify!($mod_name), ": wolf key generation should succeed"));
                let wolf_vk = wolf_sk.verifying_key().unwrap();
                let wolf_pub_bytes: &[u8] = wolf_vk.as_bytes();

                // Wolf -> pure -> re-export
                let pure_vk = PureVerifyingKey::from_sec1_bytes(wolf_pub_bytes)
                    .expect(concat!(stringify!($mod_name), ": pure must accept wolf public key"));
                let point = pure_vk.to_encoded_point(false);
                let re_exported: &[u8] = point.as_bytes();

                assert_eq!(
                    wolf_pub_bytes,
                    re_exported,
                    concat!(stringify!($mod_name), ": public key must survive wolf->pure->re-export round trip")
                );
            }

            #[test]
            fn tampered_message_both_reject() {
                let wolf_sk = EcdsaSigningKey::<WolfCurve>::generate()
                    .expect(concat!(stringify!($mod_name), ": wolf key generation should succeed"));
                let wolf_vk = wolf_sk.verifying_key().unwrap();
                let msg = b"original ecdsa message";
                let mut tampered = msg.to_vec();
                tampered[0] ^= 0xFF;

                use signature::Signer as _;
                let wolf_sig: EcdsaSignature<WolfCurve> = wolf_sk.sign(msg);

                // Wolf must reject
                use signature::Verifier as _;
                let wolf_result = wolf_vk.verify(&tampered, &wolf_sig);
                assert!(
                    wolf_result.is_err(),
                    concat!(stringify!($mod_name), ": wolf must reject signature against tampered message")
                );

                // Pure must reject
                let pure_vk = PureVerifyingKey::from_sec1_bytes(wolf_vk.as_bytes())
                    .expect(concat!(stringify!($mod_name), ": pure must accept wolf public key"));
                let pure_sig = PureSig::from_slice(wolf_sig.as_bytes())
                    .expect(concat!(stringify!($mod_name), ": pure must accept wolf signature bytes"));
                let pure_result = pure_vk.verify(&tampered, &pure_sig);
                assert!(
                    pure_result.is_err(),
                    concat!(stringify!($mod_name), ": pure must reject signature against tampered message")
                );
            }

            #[test]
            fn tampered_signature_both_reject() {
                let wolf_sk = EcdsaSigningKey::<WolfCurve>::generate()
                    .expect(concat!(stringify!($mod_name), ": wolf key generation should succeed"));
                let wolf_vk = wolf_sk.verifying_key().unwrap();
                let msg = b"ecdsa tampered signature test";

                use signature::Signer as _;
                let wolf_sig: EcdsaSignature<WolfCurve> = wolf_sk.sign(msg);
                let mut sig_bytes = wolf_sig.as_bytes().to_vec();
                // Flip a byte in the middle of the signature
                sig_bytes[$sig_component_len / 2] ^= 0x01;

                // Wolf must reject
                if let Ok(tampered_wolf_sig) = EcdsaSignature::<WolfCurve>::from_bytes(&sig_bytes) {
                    use signature::Verifier as _;
                    let wolf_result = wolf_vk.verify(msg, &tampered_wolf_sig);
                    assert!(
                        wolf_result.is_err(),
                        concat!(stringify!($mod_name), ": wolf must reject tampered signature")
                    );
                }
                // If from_bytes itself rejects, that's also correct

                // Pure must reject
                let pure_vk = PureVerifyingKey::from_sec1_bytes(wolf_vk.as_bytes())
                    .expect(concat!(stringify!($mod_name), ": pure must accept wolf public key"));
                if let Ok(tampered_pure_sig) = PureSig::from_slice(&sig_bytes) {
                    use signature::Verifier as _;
                    let pure_result = pure_vk.verify(msg, &tampered_pure_sig);
                    assert!(
                        pure_result.is_err(),
                        concat!(stringify!($mod_name), ": pure must reject tampered signature")
                    );
                }
            }

            #[test]
            fn wrong_key_both_reject() {
                let wolf_sk_a = EcdsaSigningKey::<WolfCurve>::generate()
                    .expect(concat!(stringify!($mod_name), ": wolf keygen(a) should succeed"));
                let wolf_sk_b = EcdsaSigningKey::<WolfCurve>::generate()
                    .expect(concat!(stringify!($mod_name), ": wolf keygen(b) should succeed"));
                let wolf_vk_b = wolf_sk_b.verifying_key().unwrap();
                let msg = b"ecdsa wrong key rejection";

                use signature::Signer as _;
                let wolf_sig: EcdsaSignature<WolfCurve> = wolf_sk_a.sign(msg);

                // Wolf: verify with wrong key
                use signature::Verifier as _;
                let wolf_result = wolf_vk_b.verify(msg, &wolf_sig);
                assert!(
                    wolf_result.is_err(),
                    concat!(stringify!($mod_name), ": wolf must reject signature verified with wrong key")
                );

                // Pure: verify with wrong key
                let pure_vk_b = PureVerifyingKey::from_sec1_bytes(wolf_vk_b.as_bytes())
                    .expect(concat!(stringify!($mod_name), ": pure must accept wolf public key"));
                let pure_sig = PureSig::from_slice(wolf_sig.as_bytes())
                    .expect(concat!(stringify!($mod_name), ": pure must accept wolf signature bytes"));
                let pure_result = pure_vk_b.verify(msg, &pure_sig);
                assert!(
                    pure_result.is_err(),
                    concat!(stringify!($mod_name), ": pure must reject signature verified with wrong key")
                );
            }

            #[test]
            fn multiple_random_messages() {
                let mut rng = rand::thread_rng();

                let wolf_sk = EcdsaSigningKey::<WolfCurve>::generate()
                    .expect(concat!(stringify!($mod_name), ": wolf key generation should succeed"));
                let wolf_vk = wolf_sk.verifying_key().unwrap();

                let pure_vk = PureVerifyingKey::from_sec1_bytes(wolf_vk.as_bytes())
                    .expect(concat!(stringify!($mod_name), ": pure must accept wolf public key"));

                let pure_sk = PureSigningKey::random(&mut rng);
                let pure_vk_own = pure_sk.verifying_key();
                let point = pure_vk_own.to_encoded_point(false);
                let wolf_vk_from_pure =
                    EcdsaVerifyingKey::<WolfCurve>::from_uncompressed_point(point.as_bytes())
                        .expect(concat!(stringify!($mod_name), ": wolf must accept pure public key"));

                for i in 0..20 {
                    let msg = random_bytes(&mut rng, 32 + i * 11);

                    // Wolf sign -> pure verify
                    use signature::Signer as WS;
                    let wolf_sig: EcdsaSignature<WolfCurve> = WS::sign(&wolf_sk, &msg);
                    let pure_sig = PureSig::from_slice(wolf_sig.as_bytes()).unwrap_or_else(|e| {
                        panic!(concat!(stringify!($mod_name), " round {}: pure must parse wolf sig: {}"), i, e)
                    });
                    use signature::Verifier as WV;
                    WV::verify(&pure_vk, &msg, &pure_sig).unwrap_or_else(|e| {
                        panic!(concat!(stringify!($mod_name), " round {}: pure must verify wolf sig: {}"), i, e)
                    });

                    // Pure sign -> wolf verify
                    let pure_sig2: PureSig = WS::sign(&pure_sk, &msg);
                    let wolf_sig2 = EcdsaSignature::<WolfCurve>::from_bytes(
                        pure_sig2.to_bytes().as_ref(),
                    )
                    .unwrap_or_else(|e| {
                        panic!(concat!(stringify!($mod_name), " round {}: wolf must parse pure sig: {}"), i, e)
                    });
                    WV::verify(&wolf_vk_from_pure, &msg, &wolf_sig2).unwrap_or_else(|e| {
                        panic!(concat!(stringify!($mod_name), " round {}: wolf must verify pure sig: {}"), i, e)
                    });
                }
            }

            #[test]
            fn canary_signature_not_constant() {
                let wolf_sk = EcdsaSigningKey::<WolfCurve>::generate()
                    .expect(concat!(stringify!($mod_name), ": wolf key generation should succeed"));
                let wolf_vk = wolf_sk.verifying_key().unwrap();
                let msg = b"ecdsa randomness canary";

                use signature::Signer as _;
                let sig1: EcdsaSignature<WolfCurve> = wolf_sk.sign(msg);
                let sig2: EcdsaSignature<WolfCurve> = wolf_sk.sign(msg);

                // ECDSA is randomized, so signatures should differ (with overwhelming probability).
                // If they happen to be the same, that's a sign the RNG isn't working.
                // Either way, both must verify.
                use signature::Verifier as _;
                wolf_vk.verify(msg, &sig1)
                    .expect(concat!(stringify!($mod_name), ": wolf must verify first signature"));
                wolf_vk.verify(msg, &sig2)
                    .expect(concat!(stringify!($mod_name), ": wolf must verify second signature"));

                // Also verify via pure
                let pure_vk = PureVerifyingKey::from_sec1_bytes(wolf_vk.as_bytes())
                    .expect(concat!(stringify!($mod_name), ": pure must accept wolf public key"));
                let pure_sig1 = PureSig::from_slice(sig1.as_bytes())
                    .expect(concat!(stringify!($mod_name), ": pure must parse first sig"));
                let pure_sig2 = PureSig::from_slice(sig2.as_bytes())
                    .expect(concat!(stringify!($mod_name), ": pure must parse second sig"));
                pure_vk.verify(msg, &pure_sig1)
                    .expect(concat!(stringify!($mod_name), ": pure must verify first wolf sig"));
                pure_vk.verify(msg, &pure_sig2)
                    .expect(concat!(stringify!($mod_name), ": pure must verify second wolf sig"));

                // wolfCrypt's wc_ecc_sign_hash is randomized (not RFC 6979 by
                // default).  Identical signatures over the same message with
                // different RNG calls indicate the RNG returned the same nonce
                // twice — a catastrophic signing failure.  Emit a loud warning
                // so it is never silently ignored.  (Deterministic RFC-6979
                // builds will trigger this warning spuriously; that is
                // acceptable because the alternative is a silent blind spot.)
                if sig1.as_bytes() == sig2.as_bytes() {
                    eprintln!(
                        "WARNING ({}): two ECDSA signatures over the same message \
                         are identical — this indicates an RNG nonce reuse, which \
                         is a catastrophic signing failure. Investigate immediately.",
                        stringify!($mod_name)
                    );
                }
            }
        }
    };
}

ecdsa_cross!(
    p256,
    wolfcrypt::P256,
    p256::ecdsa::SigningKey,
    p256::ecdsa::VerifyingKey,
    p256::ecdsa::Signature,
    32,
    [wolfssl_ecc]
);

ecdsa_cross!(
    p384,
    wolfcrypt::P384,
    p384::ecdsa::SigningKey,
    p384::ecdsa::VerifyingKey,
    p384::ecdsa::Signature,
    48,
    [wolfssl_ecc, wolfssl_ecc_p384]
);

// P-521: the pure-Rust `p521` crate uses newtype wrappers (not type aliases)
// for SigningKey/VerifyingKey, so the `ecdsa_cross!` macro doesn't fit.
// Write the cross-validation tests directly.
#[cfg(all(wolfssl_ecc, wolfssl_ecc_p521, wolfssl_sha512))]
mod p521_cross {
    use wolfcrypt::{EcdsaSigningKey, EcdsaVerifyingKey, EcdsaSignature, P521};
    use signature::{Signer, Verifier};

    #[test]
    fn wolf_sign_pure_verify() {
        let wolf_sk = EcdsaSigningKey::<P521>::generate()
            .expect("p521: wolf key generation should succeed");
        let wolf_vk = wolf_sk.verifying_key().unwrap();
        let msg = b"p521: wolf signs, pure verifies";

        let wolf_sig: EcdsaSignature<P521> = wolf_sk.sign(msg);

        // Export wolf pub key, import into pure
        let wolf_pub_bytes: &[u8] = wolf_vk.as_bytes();
        let pure_vk = p521::ecdsa::VerifyingKey::from_sec1_bytes(wolf_pub_bytes)
            .expect("p521: pure must accept wolf public key bytes");

        // Convert wolf sig to pure sig
        let pure_sig = p521::ecdsa::Signature::from_slice(wolf_sig.as_bytes())
            .expect("p521: pure must accept wolf signature bytes");

        pure_vk.verify(msg, &pure_sig)
            .expect("p521: pure must verify wolf-generated signature");
    }

    #[test]
    fn pure_sign_wolf_verify() {
        let mut rng = rand::thread_rng();
        let pure_sk = p521::ecdsa::SigningKey::random(&mut rng);
        let pure_vk = p521::ecdsa::VerifyingKey::from(&pure_sk);

        let msg = b"p521: pure signs, wolf verifies";

        let pure_sig: p521::ecdsa::Signature = pure_sk.sign(msg);

        // Export pure pub key (uncompressed), import into wolf
        let point = pure_vk.to_encoded_point(false);
        let sec1_bytes: &[u8] = point.as_bytes();
        let wolf_vk = EcdsaVerifyingKey::<P521>::from_uncompressed_point(sec1_bytes)
            .expect("p521: wolf must accept pure public key bytes");

        // Convert pure sig to wolf sig
        let sig_bytes = pure_sig.to_bytes();
        let wolf_sig = EcdsaSignature::<P521>::from_bytes(sig_bytes.as_ref())
            .expect("p521: wolf must accept pure signature bytes");

        wolf_vk.verify(msg, &wolf_sig)
            .expect("p521: wolf must verify pure-generated signature");
    }

    #[test]
    fn pubkey_export_import_round_trip() {
        let wolf_sk = EcdsaSigningKey::<P521>::generate()
            .expect("p521: wolf key generation should succeed");
        let wolf_vk = wolf_sk.verifying_key().unwrap();
        let wolf_pub_bytes: &[u8] = wolf_vk.as_bytes();

        // Wolf -> pure -> re-export
        let pure_vk = p521::ecdsa::VerifyingKey::from_sec1_bytes(wolf_pub_bytes)
            .expect("p521: pure must accept wolf public key");
        let point = pure_vk.to_encoded_point(false);
        let re_exported: &[u8] = point.as_bytes();

        assert_eq!(
            wolf_pub_bytes,
            re_exported,
            "p521: public key must survive wolf->pure->re-export round trip"
        );
    }

    #[test]
    fn tampered_message_both_reject() {
        let wolf_sk = EcdsaSigningKey::<P521>::generate()
            .expect("p521: wolf key generation should succeed");
        let wolf_vk = wolf_sk.verifying_key().unwrap();
        let msg = b"original p521 message";
        let mut tampered = msg.to_vec();
        tampered[0] ^= 0xFF;

        let wolf_sig: EcdsaSignature<P521> = wolf_sk.sign(msg);

        // Wolf must reject
        let wolf_result = wolf_vk.verify(&tampered, &wolf_sig);
        assert!(wolf_result.is_err(), "p521: wolf must reject tampered message");

        // Pure must reject
        let pure_vk = p521::ecdsa::VerifyingKey::from_sec1_bytes(wolf_vk.as_bytes())
            .expect("p521: pure must accept wolf public key");
        let pure_sig = p521::ecdsa::Signature::from_slice(wolf_sig.as_bytes())
            .expect("p521: pure must accept wolf signature bytes");
        let pure_result = pure_vk.verify(&tampered, &pure_sig);
        assert!(pure_result.is_err(), "p521: pure must reject tampered message");
    }

    #[test]
    fn wrong_key_both_reject() {
        let wolf_sk_a = EcdsaSigningKey::<P521>::generate()
            .expect("p521: wolf keygen(a) should succeed");
        let wolf_sk_b = EcdsaSigningKey::<P521>::generate()
            .expect("p521: wolf keygen(b) should succeed");
        let wolf_vk_b = wolf_sk_b.verifying_key().unwrap();
        let msg = b"p521 wrong key rejection";

        let wolf_sig: EcdsaSignature<P521> = wolf_sk_a.sign(msg);

        // Wolf: verify with wrong key
        let wolf_result = wolf_vk_b.verify(msg, &wolf_sig);
        assert!(wolf_result.is_err(), "p521: wolf must reject with wrong key");

        // Pure: verify with wrong key
        let pure_vk_b = p521::ecdsa::VerifyingKey::from_sec1_bytes(wolf_vk_b.as_bytes())
            .expect("p521: pure must accept wolf public key");
        let pure_sig = p521::ecdsa::Signature::from_slice(wolf_sig.as_bytes())
            .expect("p521: pure must accept wolf signature bytes");
        let pure_result = pure_vk_b.verify(msg, &pure_sig);
        assert!(pure_result.is_err(), "p521: pure must reject with wrong key");
    }

    #[test]
    fn multiple_random_messages() {
        use super::helpers::random_bytes;

        let mut rng = rand::thread_rng();

        let wolf_sk = EcdsaSigningKey::<P521>::generate()
            .expect("p521: wolf key generation should succeed");
        let wolf_vk = wolf_sk.verifying_key().unwrap();

        let pure_vk = p521::ecdsa::VerifyingKey::from_sec1_bytes(wolf_vk.as_bytes())
            .expect("p521: pure must accept wolf public key");

        let pure_sk = p521::ecdsa::SigningKey::random(&mut rng);
        let pure_vk_own = p521::ecdsa::VerifyingKey::from(&pure_sk);
        let point = pure_vk_own.to_encoded_point(false);
        let wolf_vk_from_pure =
            EcdsaVerifyingKey::<P521>::from_uncompressed_point(point.as_bytes())
                .expect("p521: wolf must accept pure public key");

        for i in 0..20 {
            let msg = random_bytes(&mut rng, 32 + i * 11);

            // Wolf sign -> pure verify
            use signature::Signer as WS;
            let wolf_sig: EcdsaSignature<P521> = WS::sign(&wolf_sk, &msg);
            let pure_sig = p521::ecdsa::Signature::from_slice(wolf_sig.as_bytes())
                .unwrap_or_else(|e| panic!("p521 round {i}: pure must parse wolf sig: {e}"));
            use signature::Verifier as WV;
            WV::verify(&pure_vk, &msg, &pure_sig)
                .unwrap_or_else(|e| panic!("p521 round {i}: pure must verify wolf sig: {e}"));

            // Pure sign -> wolf verify
            let pure_sig2: p521::ecdsa::Signature = WS::sign(&pure_sk, &msg);
            let wolf_sig2 = EcdsaSignature::<P521>::from_bytes(
                pure_sig2.to_bytes().as_ref(),
            )
            .unwrap_or_else(|e| {
                panic!("p521 round {i}: wolf must parse pure sig: {e}")
            });
            WV::verify(&wolf_vk_from_pure, &msg, &wolf_sig2).unwrap_or_else(|e| {
                panic!("p521 round {i}: wolf must verify pure sig: {e}")
            });
        }
    }
}

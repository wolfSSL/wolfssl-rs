// ACVP test vectors exist locally in vectors/acvp/ (MLDSA_{44,65,87}
// keyGen and sigVer files sourced from the NIST ACVP server), but they
// are not wired up yet for two reasons:
//
// 1. keyGen vectors require deterministic key generation from a 32-byte
//    seed.  The wolfcrypt API only exposes
//    `MlDsaSigningKey::generate(rng)` which uses a random RNG; there is
//    no `from_seed()` entry point to reproduce the expected (pk, sk) pair.
//
// 2. sigVer vectors could in principle work because
//    `MlDsaVerifyingKey::from_bytes()` exists, but the vectors also
//    carry a CONTEXT field and negative-test cases (RESULT = False) that
//    need careful handling not yet implemented.
//
// Once the API exposes deterministic keygen and the sigVer harness is
// written, these vectors should be exercised here.
//
// No pure-Rust counterpart: ml-dsa 0.0.x is API-unstable.
#![cfg(wolfssl_dilithium)]

mod helpers;

/// Generates a full suite of trait-conformance tests for ML-DSA at a given
/// security level.  No pure-Rust counterpart is used (the `ml-dsa` crate is
/// too early/unstable); these tests exercise the `signature::Signer` /
/// `signature::Verifier` traits and basic security properties.
macro_rules! mldsa_conformance {
    ($mod_name:ident, $sk_ty:ty, $vk_ty:ty, $sig_ty:ty, [$($cfg_gate:meta),*]) => {
        #[cfg(all($($cfg_gate),*))]
        mod $mod_name {
            use super::helpers::*;
            use wolfcrypt::WolfRng;

            type SigningKey = $sk_ty;
            type VerifyingKey = $vk_ty;
            type Sig = $sig_ty;

            #[test]
            fn sign_verify_round_trip() {
                let mut rng = WolfRng::new().expect("WolfRng::new must succeed");
                let sk = SigningKey::generate(&mut rng)
                    .expect(concat!(stringify!($mod_name), ": key generation must succeed"));
                let vk = sk.verifying_key();
                let msg = b"ML-DSA round-trip test message";

                use signature::Signer as _;
                let sig: Sig = sk.sign(msg);

                use signature::Verifier as _;
                vk.verify(msg, &sig).expect(concat!(
                    stringify!($mod_name),
                    ": signature verification must succeed on valid message"
                ));
            }

            #[test]
            fn tampered_message_rejected() {
                let mut rng = WolfRng::new().expect("WolfRng::new must succeed");
                let sk = SigningKey::generate(&mut rng)
                    .expect(concat!(stringify!($mod_name), ": key generation must succeed"));
                let vk = sk.verifying_key();
                let msg = b"original ML-DSA message";
                let mut tampered = msg.to_vec();
                tampered[0] ^= 0xFF;

                use signature::Signer as _;
                let sig: Sig = sk.sign(msg);

                use signature::Verifier as _;
                let result = vk.verify(&tampered, &sig);
                assert!(
                    result.is_err(),
                    concat!(stringify!($mod_name), ": verification must fail on tampered message")
                );
            }

            #[test]
            fn tampered_signature_rejected() {
                let mut rng = WolfRng::new().expect("WolfRng::new must succeed");
                let sk = SigningKey::generate(&mut rng)
                    .expect(concat!(stringify!($mod_name), ": key generation must succeed"));
                let vk = sk.verifying_key();
                let msg = b"ML-DSA tampered signature test";

                use signature::Signer as _;
                let sig: Sig = sk.sign(msg);
                let mut sig_bytes = sig.as_ref().to_vec();
                // Flip a byte near the middle
                let mid = sig_bytes.len() / 2;
                sig_bytes[mid] ^= 0x01;

                // Attempt to reconstruct the signature from tampered bytes
                if let Ok(tampered_sig) = <Sig as TryFrom<&[u8]>>::try_from(&sig_bytes) {
                    use signature::Verifier as _;
                    let result = vk.verify(msg, &tampered_sig);
                    assert!(
                        result.is_err(),
                        concat!(stringify!($mod_name), ": verification must fail on tampered signature")
                    );
                }
                // If TryFrom rejects the tampered bytes, that is also correct.
            }

            #[test]
            fn wrong_key_rejected() {
                let mut rng = WolfRng::new().expect("WolfRng::new must succeed");
                let sk_a = SigningKey::generate(&mut rng)
                    .expect(concat!(stringify!($mod_name), ": keygen(a) must succeed"));
                let sk_b = SigningKey::generate(&mut rng)
                    .expect(concat!(stringify!($mod_name), ": keygen(b) must succeed"));
                let vk_b = sk_b.verifying_key();
                let msg = b"ML-DSA wrong key rejection test";

                use signature::Signer as _;
                let sig: Sig = sk_a.sign(msg);

                use signature::Verifier as _;
                let result = vk_b.verify(msg, &sig);
                assert!(
                    result.is_err(),
                    concat!(stringify!($mod_name), ": verification with wrong public key must fail")
                );
            }

            #[test]
            fn signature_encoding_round_trip() {
                let mut rng = WolfRng::new().expect("WolfRng::new must succeed");
                let sk = SigningKey::generate(&mut rng)
                    .expect(concat!(stringify!($mod_name), ": key generation must succeed"));
                let vk = sk.verifying_key();
                let msg = b"ML-DSA encoding round trip";

                use signature::Signer as _;
                let sig: Sig = sk.sign(msg);

                // Round-trip through raw bytes
                let sig_bytes = sig.as_ref().to_vec();
                let sig2 = <Sig as TryFrom<&[u8]>>::try_from(&sig_bytes)
                    .expect(concat!(stringify!($mod_name), ": signature must round-trip through bytes"));

                // The reconstructed signature must still verify
                use signature::Verifier as _;
                vk.verify(msg, &sig2).expect(concat!(
                    stringify!($mod_name),
                    ": round-tripped signature must still verify"
                ));

                // Bytes must be identical
                assert_eq!(
                    sig.as_ref(),
                    sig2.as_ref(),
                    concat!(stringify!($mod_name), ": signature bytes must be identical after round trip")
                );
            }

            #[test]
            fn verifying_key_round_trip() {
                let mut rng = WolfRng::new().expect("WolfRng::new must succeed");
                let sk = SigningKey::generate(&mut rng)
                    .expect(concat!(stringify!($mod_name), ": key generation must succeed"));
                let vk = sk.verifying_key();
                let msg = b"ML-DSA verifying key round trip";

                use signature::Signer as _;
                let sig: Sig = sk.sign(msg);

                // Export verifying key bytes, reimport
                let vk_bytes = vk.as_bytes().to_vec();
                let vk2 = VerifyingKey::from_bytes(&vk_bytes)
                    .expect(concat!(stringify!($mod_name), ": verifying key must round-trip through bytes"));

                // Re-imported key must verify the same signature
                use signature::Verifier as _;
                vk2.verify(msg, &sig).expect(concat!(
                    stringify!($mod_name),
                    ": reimported verifying key must verify original signature"
                ));

                // Exported bytes must be identical
                assert_eq!(
                    vk.as_bytes(),
                    vk2.as_bytes(),
                    concat!(stringify!($mod_name), ": verifying key bytes must survive export/import round trip")
                );
            }

            #[test]
            fn multiple_random_messages() {
                let mut rng = WolfRng::new().expect("WolfRng::new must succeed");
                let mut thread_rng = rand::thread_rng();
                let sk = SigningKey::generate(&mut rng)
                    .expect(concat!(stringify!($mod_name), ": key generation must succeed"));
                let vk = sk.verifying_key();

                for i in 0..50 {
                    let msg = random_bytes(&mut thread_rng, 16 + i * 7);

                    use signature::Signer as _;
                    let sig: Sig = sk.sign(&msg);

                    use signature::Verifier as _;
                    vk.verify(&msg, &sig).unwrap_or_else(|e| {
                        panic!(
                            concat!(stringify!($mod_name), " round {}: sign+verify must succeed: {}"),
                            i, e
                        )
                    });
                }
            }

            #[test]
            fn different_keys_different_signatures() {
                let mut rng = WolfRng::new().expect("WolfRng::new must succeed");
                let sk_a = SigningKey::generate(&mut rng)
                    .expect(concat!(stringify!($mod_name), ": keygen(a) must succeed"));
                let sk_b = SigningKey::generate(&mut rng)
                    .expect(concat!(stringify!($mod_name), ": keygen(b) must succeed"));
                let msg = b"same message, different keys";

                use signature::Signer as _;
                let sig_a: Sig = sk_a.sign(msg);
                let sig_b: Sig = sk_b.sign(msg);

                assert_ne!(
                    sig_a.as_ref(),
                    sig_b.as_ref(),
                    concat!(stringify!($mod_name), ": different keys must produce different signatures on the same message")
                );
            }
        }
    };
}

mldsa_conformance!(
    mldsa44,
    wolfcrypt::MlDsa44SigningKey,
    wolfcrypt::mldsa::MlDsaVerifyingKey<wolfcrypt::mldsa::MlDsa44>,
    wolfcrypt::MlDsa44Signature,
    [wolfssl_dilithium]
);

mldsa_conformance!(
    mldsa65,
    wolfcrypt::MlDsa65SigningKey,
    wolfcrypt::mldsa::MlDsaVerifyingKey<wolfcrypt::mldsa::MlDsa65>,
    wolfcrypt::MlDsa65Signature,
    [wolfssl_dilithium]
);

mldsa_conformance!(
    mldsa87,
    wolfcrypt::MlDsa87SigningKey,
    wolfcrypt::mldsa::MlDsaVerifyingKey<wolfcrypt::mldsa::MlDsa87>,
    wolfcrypt::MlDsa87Signature,
    [wolfssl_dilithium]
);

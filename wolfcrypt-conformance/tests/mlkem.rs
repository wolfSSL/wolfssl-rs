// TODO: add NIST ACVP / FIPS 203 known-answer vectors when stable test
// vectors are widely available. Currently wolf-only round-trip tests.
// No pure-Rust counterpart: ml-kem depends on pre-release kem 0.3.0-pre.0.
#![cfg(wolfssl_mlkem)]

mod helpers;

/// Generates a full suite of trait-conformance tests for ML-KEM at a given
/// security level.  No pure-Rust counterpart is used (the `ml-kem` crate
/// depends on a pre-release `kem` trait); these tests exercise the wolfCrypt
/// ML-KEM API and basic security properties.
macro_rules! mlkem_conformance {
    ($mod_name:ident, $dk_ty:ty, $ek_ty:ty, [$($cfg_gate:meta),*]) => {
        #[cfg(all($($cfg_gate),*))]
        mod $mod_name {
            type DecapsulationKey = $dk_ty;
            type EncapsulationKey = $ek_ty;

            #[test]
            fn encap_decap_round_trip() {
                let dk = DecapsulationKey::generate()
                    .expect(concat!(stringify!($mod_name), ": key generation must succeed"));
                let mut ek = dk.encapsulation_key()
                    .expect(concat!(stringify!($mod_name), ": encapsulation key derivation must succeed"));

                let (ct, ss_enc) = ek.encapsulate()
                    .expect(concat!(stringify!($mod_name), ": encapsulation must succeed"));

                let ss_dec = dk.decapsulate(&ct)
                    .expect(concat!(stringify!($mod_name), ": decapsulation must succeed"));

                assert_eq!(
                    ss_enc.as_bytes(),
                    ss_dec.as_bytes(),
                    concat!(stringify!($mod_name), ": encapsulated and decapsulated shared secrets must match")
                );
            }

            #[test]
            fn wrong_dk_produces_different_ss() {
                let dk_a = DecapsulationKey::generate()
                    .expect(concat!(stringify!($mod_name), ": keygen(a) must succeed"));
                let dk_b = DecapsulationKey::generate()
                    .expect(concat!(stringify!($mod_name), ": keygen(b) must succeed"));

                let mut ek_a = dk_a.encapsulation_key()
                    .expect(concat!(stringify!($mod_name), ": encapsulation key(a) must succeed"));

                let (ct, ss_enc) = ek_a.encapsulate()
                    .expect(concat!(stringify!($mod_name), ": encapsulation must succeed"));

                // ML-KEM is IND-CCA2: decapsulation with the wrong key "succeeds"
                // but produces a different (implicit-rejection) shared secret.
                let ss_wrong = dk_b.decapsulate(&ct)
                    .expect(concat!(stringify!($mod_name), ": decapsulation with wrong key must not error"));

                assert_ne!(
                    ss_enc.as_bytes(),
                    ss_wrong.as_bytes(),
                    concat!(stringify!($mod_name), ": wrong decapsulation key must produce a different shared secret")
                );
            }

            #[test]
            fn encapsulation_key_bytes_round_trip() {
                let dk = DecapsulationKey::generate()
                    .expect(concat!(stringify!($mod_name), ": key generation must succeed"));

                // Export public key bytes
                let pk_bytes = dk.public_key_bytes()
                    .expect(concat!(stringify!($mod_name), ": public key export must succeed"));

                // Re-import as a standalone encapsulation key
                let mut ek_reimported = EncapsulationKey::from_bytes(&pk_bytes)
                    .expect(concat!(stringify!($mod_name), ": public key re-import must succeed"));

                // Re-exported bytes must match
                let pk_bytes_2 = ek_reimported.as_bytes()
                    .expect(concat!(stringify!($mod_name), ": re-exported public key bytes must succeed"));
                assert_eq!(
                    pk_bytes,
                    pk_bytes_2,
                    concat!(stringify!($mod_name), ": public key bytes must survive export/import round trip")
                );

                // Encapsulation with reimported key must produce a valid ciphertext
                let (ct, ss_enc) = ek_reimported.encapsulate()
                    .expect(concat!(stringify!($mod_name), ": encapsulation with reimported key must succeed"));

                let ss_dec = dk.decapsulate(&ct)
                    .expect(concat!(stringify!($mod_name), ": decapsulation of reimported-key ciphertext must succeed"));

                assert_eq!(
                    ss_enc.as_bytes(),
                    ss_dec.as_bytes(),
                    concat!(stringify!($mod_name), ": shared secret must match after key round-trip")
                );
            }

            #[test]
            fn multiple_encapsulations() {
                let dk = DecapsulationKey::generate()
                    .expect(concat!(stringify!($mod_name), ": key generation must succeed"));
                let mut ek = dk.encapsulation_key()
                    .expect(concat!(stringify!($mod_name), ": encapsulation key derivation must succeed"));

                let mut prev_ct: Option<Vec<u8>> = None;
                let mut prev_ss: Option<Vec<u8>> = None;

                for i in 0..20 {
                    let (ct, ss_enc) = ek.encapsulate()
                        .unwrap_or_else(|e| panic!(
                            concat!(stringify!($mod_name), " round {}: encapsulation must succeed: {}"),
                            i, e
                        ));

                    let ss_dec = dk.decapsulate(&ct)
                        .unwrap_or_else(|e| panic!(
                            concat!(stringify!($mod_name), " round {}: decapsulation must succeed: {}"),
                            i, e
                        ));

                    assert_eq!(
                        ss_enc.as_bytes(),
                        ss_dec.as_bytes(),
                        concat!(stringify!($mod_name), " round {}: shared secrets must match"),
                        i
                    );

                    // Each encapsulation should produce a different ciphertext and
                    // shared secret (ML-KEM encapsulation is randomized).
                    if let Some(ref prev) = prev_ct {
                        assert_ne!(
                            &ct, prev,
                            concat!(stringify!($mod_name), " round {}: ciphertexts must differ across encapsulations"),
                            i
                        );
                    }
                    if let Some(ref prev) = prev_ss {
                        assert_ne!(
                            ss_enc.as_bytes(), prev.as_slice(),
                            concat!(stringify!($mod_name), " round {}: shared secrets must differ across encapsulations"),
                            i
                        );
                    }

                    prev_ct = Some(ct);
                    prev_ss = Some(ss_enc.as_bytes().to_vec());
                }
            }

            #[test]
            fn tampered_ct_different_ss() {
                let dk = DecapsulationKey::generate()
                    .expect(concat!(stringify!($mod_name), ": key generation must succeed"));
                let mut ek = dk.encapsulation_key()
                    .expect(concat!(stringify!($mod_name), ": encapsulation key derivation must succeed"));

                let (ct, ss_original) = ek.encapsulate()
                    .expect(concat!(stringify!($mod_name), ": encapsulation must succeed"));

                // Flip a byte in the middle of the ciphertext
                let mut tampered_ct = ct.clone();
                let mid = tampered_ct.len() / 2;
                tampered_ct[mid] ^= 0x01;

                // ML-KEM IND-CCA2: decapsulation of tampered CT should succeed
                // but produce a different (implicit-rejection) shared secret.
                let ss_tampered = dk.decapsulate(&tampered_ct)
                    .expect(concat!(stringify!($mod_name), ": decapsulation of tampered CT must not error (implicit rejection)"));

                assert_ne!(
                    ss_original.as_bytes(),
                    ss_tampered.as_bytes(),
                    concat!(stringify!($mod_name), ": tampered ciphertext must produce a different shared secret")
                );
            }
        }
    };
}

mlkem_conformance!(
    mlkem512,
    wolfcrypt::MlKem512DecapsulationKey,
    wolfcrypt::MlKem512EncapsulationKey,
    [wolfssl_mlkem]
);

mlkem_conformance!(
    mlkem768,
    wolfcrypt::MlKem768DecapsulationKey,
    wolfcrypt::MlKem768EncapsulationKey,
    [wolfssl_mlkem]
);

mlkem_conformance!(
    mlkem1024,
    wolfcrypt::MlKem1024DecapsulationKey,
    wolfcrypt::MlKem1024EncapsulationKey,
    [wolfssl_mlkem]
);

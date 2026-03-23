//! Alias key management tests.
//!
//! Wolf-specific: `WolfCryptDpeImpl` has `set_alias_key(priv_key, pub_key)`.
//! Before alias is set, `sign_with_alias()` returns `CryptoError::CryptoLibError(0x04_0000)`.
//! The reference backend always has a built-in alias key.

mod helpers;

macro_rules! alias_key_tests {
    (
        $mod_name:ident,
        $new_wolf:path,
        $make_meas:path,
        $verify_sig:path,
        $variant:expr
    ) => {
        mod $mod_name {
            use crate::helpers;
            use caliptra_dpe_crypto::{Crypto, CryptoError, Digest, SignData};

            #[test]
            fn sign_with_alias_before_set_fails_wolf() {
                let mut wolf = $new_wolf();
                let measurement = $make_meas(0xAA);
                let sign_data = SignData::Digest(measurement);
                match wolf.sign_with_alias(&sign_data) {
                    Err(CryptoError::CryptoLibError(0x04_0000)) => {}
                    Err(other) => panic!(
                        "{}: expected CryptoLibError(0x04_0000) for wolf alias-not-set, got {:?}",
                        $variant, other
                    ),
                    Ok(_) => panic!(
                        "{}: sign_with_alias should fail before alias key is set",
                        $variant
                    ),
                }
            }

            #[test]
            fn sign_with_alias_after_set_succeeds() {
                let mut wolf = $new_wolf();
                let measurement = $make_meas(0xBB);
                let cdi = wolf
                    .derive_cdi(&measurement, b"alias-test")
                    .expect("derive_cdi should succeed");
                let (priv_key, pub_key) = wolf
                    .derive_key_pair(&cdi, b"alias-label", b"alias-info")
                    .expect("derive_key_pair should succeed");

                wolf.set_alias_key(priv_key, pub_key.clone()).unwrap();

                let sign_data = SignData::Digest($make_meas(0xCC));
                let sig = wolf
                    .sign_with_alias(&sign_data)
                    .expect("sign_with_alias should succeed after setting alias key");

                // Verify independently
                let pk_bytes = helpers::pubkey_to_uncompressed(&pub_key);
                let sig_bytes = helpers::sig_to_fixed(&sig);
                let msg_digest = $make_meas(0xCC);
                let digest_bytes = helpers::digest_bytes(&msg_digest);
                $verify_sig(&pk_bytes, digest_bytes, &sig_bytes).expect(
                    concat!($variant, ": independent verification of alias signature failed"),
                );
            }

            #[test]
            fn sign_with_alias_cross_verify() {
                let mut wolf = $new_wolf();
                let measurement = $make_meas(0x11);
                let cdi = wolf
                    .derive_cdi(&measurement, b"cross-verify")
                    .expect("derive_cdi should succeed");
                let (priv_key, pub_key) = wolf
                    .derive_key_pair(&cdi, b"cv-label", b"cv-info")
                    .expect("derive_key_pair should succeed");

                wolf.set_alias_key(priv_key, pub_key.clone()).unwrap();

                let msg_digest = $make_meas(0x22);
                let sign_data = SignData::Digest(msg_digest.clone());
                let sig = wolf
                    .sign_with_alias(&sign_data)
                    .expect("sign_with_alias should succeed");

                let pk_bytes = helpers::pubkey_to_uncompressed(&pub_key);
                let sig_bytes = helpers::sig_to_fixed(&sig);
                let digest_bytes = helpers::digest_bytes(&msg_digest);

                $verify_sig(&pk_bytes, digest_bytes, &sig_bytes).expect(
                    concat!($variant, ": cross-verification of alias signature failed"),
                );
            }

            #[test]
            fn alias_key_replacement() {
                let mut wolf = $new_wolf();

                // Derive two different key pairs
                let meas_a = $make_meas(0x01);
                let cdi_a = wolf.derive_cdi(&meas_a, b"replacement-a").unwrap();
                let (priv_a, pub_a) = wolf
                    .derive_key_pair(&cdi_a, b"label-a", b"info-a")
                    .unwrap();

                let meas_b = $make_meas(0x02);
                let cdi_b = wolf.derive_cdi(&meas_b, b"replacement-b").unwrap();
                let (priv_b, pub_b) = wolf
                    .derive_key_pair(&cdi_b, b"label-b", b"info-b")
                    .unwrap();

                let msg = $make_meas(0xDD);

                // Sign with alias A
                wolf.set_alias_key(priv_a, pub_a.clone()).unwrap();
                let sig_a = wolf
                    .sign_with_alias(&SignData::Digest(msg.clone()))
                    .expect("sign with alias A should succeed");

                // Replace with alias B and sign again
                wolf.set_alias_key(priv_b, pub_b.clone()).unwrap();
                let sig_b = wolf
                    .sign_with_alias(&SignData::Digest(msg.clone()))
                    .expect("sign with alias B should succeed");

                // Signatures must differ (different keys, even same message)
                let sig_a_bytes = helpers::sig_to_fixed(&sig_a);
                let sig_b_bytes = helpers::sig_to_fixed(&sig_b);
                assert_ne!(
                    sig_a_bytes, sig_b_bytes,
                    "{}: alias replacement should produce different signatures",
                    $variant
                );

                // Verify each with its own public key
                let digest_bytes = helpers::digest_bytes(&msg);
                $verify_sig(
                    &helpers::pubkey_to_uncompressed(&pub_a),
                    digest_bytes,
                    &sig_a_bytes,
                )
                .expect(concat!($variant, ": sig_a should verify with pub_a"));
                $verify_sig(
                    &helpers::pubkey_to_uncompressed(&pub_b),
                    digest_bytes,
                    &sig_b_bytes,
                )
                .expect(concat!($variant, ": sig_b should verify with pub_b"));
            }

            #[test]
            fn alias_and_derived_independent() {
                let mut wolf = $new_wolf();

                // Derive alias key pair
                let meas_alias = $make_meas(0xA0);
                let cdi_alias = wolf.derive_cdi(&meas_alias, b"alias-ind").unwrap();
                let (alias_priv, alias_pub) = wolf
                    .derive_key_pair(&cdi_alias, b"alias-lbl", b"alias-inf")
                    .unwrap();
                wolf.set_alias_key(alias_priv, alias_pub.clone()).unwrap();

                // Derive a separate key pair for sign_with_derived
                let meas_derived = $make_meas(0xD0);
                let cdi_derived = wolf.derive_cdi(&meas_derived, b"derived-ind").unwrap();
                let (derived_priv, derived_pub) = wolf
                    .derive_key_pair(&cdi_derived, b"derived-lbl", b"derived-inf")
                    .unwrap();

                let msg = $make_meas(0xEE);
                let alias_sig = wolf
                    .sign_with_alias(&SignData::Digest(msg.clone()))
                    .expect("sign_with_alias should succeed");
                let derived_sig = wolf
                    .sign_with_derived(&SignData::Digest(msg.clone()), &derived_priv, &derived_pub)
                    .expect("sign_with_derived should succeed");

                // Public keys must differ
                let alias_pk = helpers::pubkey_to_uncompressed(&alias_pub);
                let derived_pk = helpers::pubkey_to_uncompressed(&derived_pub);
                assert_ne!(
                    alias_pk, derived_pk,
                    "{}: alias and derived public keys should differ",
                    $variant
                );

                // Each signature should verify with its own public key
                let digest_bytes = helpers::digest_bytes(&msg);
                $verify_sig(&alias_pk, digest_bytes, &helpers::sig_to_fixed(&alias_sig))
                    .expect(concat!($variant, ": alias sig should verify with alias pk"));
                $verify_sig(
                    &derived_pk,
                    digest_bytes,
                    &helpers::sig_to_fixed(&derived_sig),
                )
                .expect(concat!(
                    $variant,
                    ": derived sig should verify with derived pk"
                ));
            }
        }
    };
}

alias_key_tests!(
    p384,
    helpers::new_wolf_384,
    helpers::fixed_measurement_384,
    helpers::verify_p384_signature,
    "P-384"
);

alias_key_tests!(
    p256,
    helpers::new_wolf_256,
    helpers::fixed_measurement_256,
    helpers::verify_p256_signature,
    "P-256"
);

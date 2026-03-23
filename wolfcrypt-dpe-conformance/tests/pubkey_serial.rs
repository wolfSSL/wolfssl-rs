//! Tests for `CryptoSuite::get_pubkey_serial` equivalence between backends.
//!
//! The default implementation hashes the uncompressed public key and writes
//! the result as hex. Both backends should produce identical serial bytes
//! for the same public key.

mod helpers;

macro_rules! pubkey_serial_tests {
    (
        $mod_name:ident,
        $new_wolf:path,
        $new_ref:path,
        $make_meas:path,
        $digest_size:expr,
        $variant:expr
    ) => {
        mod $mod_name {
            use crate::helpers;
            use caliptra_dpe_crypto::{Crypto, CryptoSuite};

            /// Helper: derive a key pair from the wolf backend and return the public key.
            fn derive_pubkey_wolf(pattern: u8) -> caliptra_dpe_crypto::PubKey {
                let mut wolf = $new_wolf();
                let measurement = $make_meas(pattern);
                let cdi = wolf.derive_cdi(&measurement, b"serial-test").unwrap();
                let (_priv_key, pub_key) = wolf
                    .derive_key_pair(&cdi, b"serial-label", b"serial-info")
                    .unwrap();
                pub_key
            }

            #[test]
            fn serial_equiv() {
                let pub_key = derive_pubkey_wolf(0xAA);

                let serial_len = $digest_size * 2;
                let mut wolf_serial = vec![0u8; serial_len];
                let mut ref_serial = vec![0u8; serial_len];

                let mut wolf = $new_wolf();
                let mut refb = $new_ref();

                wolf.get_pubkey_serial(&pub_key, &mut wolf_serial)
                    .expect("wolf get_pubkey_serial should succeed");
                refb.get_pubkey_serial(&pub_key, &mut ref_serial)
                    .expect("ref get_pubkey_serial should succeed");

                assert_eq!(
                    wolf_serial, ref_serial,
                    "{}: wolf and ref should produce identical pubkey serial for the same key",
                    $variant
                );
            }

            #[test]
            fn serial_is_hex() {
                let pub_key = derive_pubkey_wolf(0xBB);

                let serial_len = $digest_size * 2;
                let mut serial = vec![0u8; serial_len];

                let mut wolf = $new_wolf();
                wolf.get_pubkey_serial(&pub_key, &mut serial)
                    .expect("get_pubkey_serial should succeed");

                for (i, &byte) in serial.iter().enumerate() {
                    let ch = byte as char;
                    assert!(
                        ch.is_ascii_hexdigit(),
                        "{}: serial byte at index {} is '{}' (0x{:02x}), expected hex [0-9a-fA-F]",
                        $variant,
                        i,
                        ch,
                        byte
                    );
                }
            }

            #[test]
            fn different_keys_different_serials() {
                let pub_key_a = derive_pubkey_wolf(0x01);
                let pub_key_b = derive_pubkey_wolf(0x02);

                let serial_len = $digest_size * 2;
                let mut serial_a = vec![0u8; serial_len];
                let mut serial_b = vec![0u8; serial_len];

                let mut wolf = $new_wolf();
                wolf.get_pubkey_serial(&pub_key_a, &mut serial_a)
                    .expect("get_pubkey_serial for key A should succeed");

                // Need a fresh instance since get_pubkey_serial takes &mut self
                let mut wolf2 = $new_wolf();
                wolf2
                    .get_pubkey_serial(&pub_key_b, &mut serial_b)
                    .expect("get_pubkey_serial for key B should succeed");

                assert_ne!(
                    serial_a, serial_b,
                    "{}: different public keys should produce different serial numbers",
                    $variant
                );
            }
        }
    };
}

pubkey_serial_tests!(
    p384,
    helpers::new_wolf_384,
    helpers::new_ref_384,
    helpers::fixed_measurement_384,
    48, // SHA-384 digest size
    "P-384"
);

pubkey_serial_tests!(
    p256,
    helpers::new_wolf_256,
    helpers::new_ref_256,
    helpers::fixed_measurement_256,
    32, // SHA-256 digest size
    "P-256"
);

#![allow(unused)]

pub mod cavp;
pub mod wycheproof;

/// Cross-validation test suite for any MAC algorithm (HMAC, CMAC, etc.).
///
/// Both types must implement `digest::Mac`. The `$label` is used in assert
/// messages (e.g. "HMAC", "CMAC").
macro_rules! mac_equiv {
    ($mod_name:ident, $wolf:ty, $pure:ty, $key_len:expr, $label:expr, [$($cfg_gate:meta),*]) => {
        #[cfg(all($($cfg_gate),*))]
        mod $mod_name {
            use super::helpers::*;
            use digest::Mac;
            use rand::Rng;

            type Wolf = $wolf;
            type Pure = $pure;

            #[test]
            fn fixed_equiv() {
                let key = vec![0x42u8; $key_len];
                let msg = concat!("fixed test message for ", $label, " cross-validation").as_bytes();

                let mut wolf = Wolf::new_from_slice(&key)
                    .expect("wolf: key slice should be valid");
                wolf.update(msg);
                let wolf_out = wolf.finalize().into_bytes();

                let mut pure = Pure::new_from_slice(&key)
                    .expect("pure: key slice should be valid");
                pure.update(msg);
                let pure_out = pure.finalize().into_bytes();

                assert_eq!(
                    wolf_out.as_slice(),
                    pure_out.as_slice(),
                    "{}: fixed key+message {} mismatch",
                    stringify!($mod_name),
                    $label
                );
            }

            #[test]
            fn random_equiv() {
                let mut rng = rand::thread_rng();
                let key = random_bytes(&mut rng, $key_len);

                for &len in HASH_LENGTHS {
                    let msg = random_bytes(&mut rng, len);

                    let mut wolf = Wolf::new_from_slice(&key)
                        .expect("wolf: key slice should be valid");
                    wolf.update(&msg);
                    let wolf_out = wolf.finalize().into_bytes();

                    let mut pure = Pure::new_from_slice(&key)
                        .expect("pure: key slice should be valid");
                    pure.update(&msg);
                    let pure_out = pure.finalize().into_bytes();

                    assert_eq!(
                        wolf_out.as_slice(),
                        pure_out.as_slice(),
                        "{}: random {} mismatch at message length {}",
                        stringify!($mod_name),
                        $label,
                        len
                    );
                }
            }

            #[test]
            fn incremental_equiv() {
                let mut rng = rand::thread_rng();
                let key = random_bytes(&mut rng, $key_len);
                let msg = random_bytes(&mut rng, 1024);

                let mut wolf = Wolf::new_from_slice(&key)
                    .expect("wolf: key slice should be valid");
                let mut offset = 0;
                while offset < msg.len() {
                    let chunk_size = rng.gen_range(1..=std::cmp::min(64, msg.len() - offset));
                    wolf.update(&msg[offset..offset + chunk_size]);
                    offset += chunk_size;
                }
                let wolf_out = wolf.finalize().into_bytes();

                let mut pure = Pure::new_from_slice(&key)
                    .expect("pure: key slice should be valid");
                pure.update(&msg);
                let pure_out = pure.finalize().into_bytes();

                assert_eq!(
                    wolf_out.as_slice(),
                    pure_out.as_slice(),
                    "{}: incremental vs one-shot {} mismatch",
                    stringify!($mod_name),
                    $label
                );
            }

            #[test]
            fn verify_cross() {
                let mut rng = rand::thread_rng();
                let key = random_bytes(&mut rng, $key_len);
                let msg = random_bytes(&mut rng, 256);

                // Compute with wolf, verify with pure
                let mut wolf = Wolf::new_from_slice(&key)
                    .expect("wolf: key slice should be valid");
                wolf.update(&msg);
                let wolf_tag = wolf.finalize().into_bytes();

                let mut pure_verifier = Pure::new_from_slice(&key)
                    .expect("pure: key slice should be valid");
                pure_verifier.update(&msg);
                assert!(
                    pure_verifier.verify_slice(&wolf_tag).is_ok(),
                    "{}: pure failed to verify wolf-generated {} tag",
                    stringify!($mod_name),
                    $label
                );

                // Compute with pure, verify with wolf
                let mut pure = Pure::new_from_slice(&key)
                    .expect("pure: key slice should be valid");
                pure.update(&msg);
                let pure_tag = pure.finalize().into_bytes();

                let mut wolf_verifier = Wolf::new_from_slice(&key)
                    .expect("wolf: key slice should be valid");
                wolf_verifier.update(&msg);
                assert!(
                    wolf_verifier.verify_slice(&pure_tag).is_ok(),
                    "{}: wolf failed to verify pure-generated {} tag",
                    stringify!($mod_name),
                    $label
                );
            }

            #[test]
            fn wrong_key_both_reject() {
                let mut rng = rand::thread_rng();
                let key_a = random_bytes(&mut rng, $key_len);
                let key_b = random_bytes(&mut rng, $key_len);
                let msg = b"message for wrong-key test";

                // Compute with key_a
                let mut wolf_a = Wolf::new_from_slice(&key_a)
                    .expect("wolf: key slice should be valid");
                wolf_a.update(msg);
                let tag_a = wolf_a.finalize().into_bytes();

                // Verify with key_b — both should reject
                let mut wolf_b = Wolf::new_from_slice(&key_b)
                    .expect("wolf: key slice should be valid");
                wolf_b.update(msg);
                assert!(
                    wolf_b.verify_slice(&tag_a).is_err(),
                    "{}: wolf should reject {} tag computed with different key",
                    stringify!($mod_name),
                    $label
                );

                let mut pure_b = Pure::new_from_slice(&key_b)
                    .expect("pure: key slice should be valid");
                pure_b.update(msg);
                assert!(
                    pure_b.verify_slice(&tag_a).is_err(),
                    "{}: pure should reject {} tag computed with different key",
                    stringify!($mod_name),
                    $label
                );
            }

            #[test]
            fn canary_wrong_key() {
                let mut rng = rand::thread_rng();
                let key_a = random_bytes(&mut rng, $key_len);
                let key_b = random_bytes(&mut rng, $key_len);
                let msg = b"canary wrong key test message";

                let mut wolf = Wolf::new_from_slice(&key_a)
                    .expect("wolf: key slice should be valid");
                wolf.update(msg);
                let wolf_out = wolf.finalize().into_bytes();

                let mut pure = Pure::new_from_slice(&key_b)
                    .expect("pure: key slice should be valid");
                pure.update(msg);
                let pure_out = pure.finalize().into_bytes();

                assert_ne!(
                    wolf_out.as_slice(),
                    pure_out.as_slice(),
                    "{}: {} with different keys should produce different tags",
                    stringify!($mod_name),
                    $label
                );
            }
        }
    };
}

pub(crate) use mac_equiv;

use cipher::generic_array::GenericArray;
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use rand::RngCore;

/// Generate a random byte vector of the given length.
/// Each test should call this with its own rng to avoid shared state.
pub fn random_bytes(rng: &mut impl RngCore, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    rng.fill_bytes(&mut buf);
    buf
}

/// Standard set of lengths to test for symmetric algorithms.
/// Covers: empty, sub-block, block-aligned, block+1, large.
pub const SYMMETRIC_LENGTHS: &[usize] = &[
    0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 128, 255, 256, 1024, 4096, 65536,
];

/// Standard set of lengths for digest/MAC tests.
/// Covers block-boundary edges for SHA-256 (64-byte blocks) and SHA-512
/// (128-byte blocks), plus large inputs.
pub const HASH_LENGTHS: &[usize] = &[
    0, 1, 55, 56, 63, 64, 65, 127, 128, 135, 136, 256, 1024, 4096, 65536,
];

/// Lengths for block-cipher tests.  All are multiples of 16 (AES block size).
pub const BLOCK_ALIGNED_LENGTHS: &[usize] = &[16, 32, 48, 64, 128, 256, 1024, 4096];

/// Encrypt plaintext block-by-block using any `BlockEncryptMut + KeyIvInit` cipher.
/// Block size is derived from the cipher's associated type, so this works for
/// both AES (16-byte blocks) and 3DES (8-byte blocks).
pub fn encrypt_blocks_with<E: BlockEncryptMut + KeyIvInit>(
    key: &[u8],
    iv: &[u8],
    pt: &[u8],
) -> Vec<u8> {
    let mut enc = E::new(
        GenericArray::from_slice(key),
        GenericArray::from_slice(iv),
    );
    let mut blocks: Vec<_> = pt
        .chunks(E::block_size())
        .map(|c| GenericArray::clone_from_slice(c))
        .collect();
    enc.encrypt_blocks_mut(&mut blocks);
    blocks.iter().flat_map(|b| b.iter().copied()).collect()
}

/// Decrypt ciphertext block-by-block using any `BlockDecryptMut + KeyIvInit` cipher.
pub fn decrypt_blocks_with<D: BlockDecryptMut + KeyIvInit>(
    key: &[u8],
    iv: &[u8],
    ct: &[u8],
) -> Vec<u8> {
    let mut dec = D::new(
        GenericArray::from_slice(key),
        GenericArray::from_slice(iv),
    );
    let mut blocks: Vec<_> = ct
        .chunks(D::block_size())
        .map(|c| GenericArray::clone_from_slice(c))
        .collect();
    dec.decrypt_blocks_mut(&mut blocks);
    blocks.iter().flat_map(|b| b.iter().copied()).collect()
}

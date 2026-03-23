#![cfg(wolfssl_chacha20_poly1305)]

mod helpers;

use aead::{AeadInPlace, KeyInit, Nonce};
use generic_array::GenericArray;
use hex_literal::hex;

/// RFC 8439 Section 2.8.2 -- ChaCha20-Poly1305 AEAD test vector.
///
/// This is the primary AEAD construction test vector from the RFC, covering
/// encryption with associated data.

const RFC8439_KEY: [u8; 32] =
    hex!("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
const RFC8439_NONCE: [u8; 12] = hex!("070000004041424344454647");
const RFC8439_AAD: [u8; 12] = hex!("50515253c0c1c2c3c4c5c6c7");
const RFC8439_PT: [u8; 114] = hex!(
    "4c616469657320616e642047656e746c"
    "656d656e206f662074686520636c6173"
    "73206f66202739393a20496620492063"
    "6f756c64206f6666657220796f75206f"
    "6e6c79206f6e652074697020666f7220"
    "746865206675747572652c2073756e73"
    "637265656e20776f756c642062652069"
    "742e"
);
const RFC8439_CT: [u8; 114] = hex!(
    "d31a8d34648e60db7b86afbc53ef7ec2"
    "a4aded51296e08fea9e2b5a736ee62d6"
    "3dbea45e8ca9671282fafb69da92728b"
    "1a71de0a9e060b2905d6a5b67ecd3b36"
    "92ddbd7f2d778b8c9803aee328091b58"
    "fab324e4fad675945585808b4831d7bc"
    "3ff4def08e4b7a9de576d26586cec64b"
    "6116"
);
const RFC8439_TAG: [u8; 16] = hex!("1ae10b594f09e26a7e902ecbd0600691");

/// Wolf encryption must produce the exact ciphertext and tag from the RFC.
#[test]
fn rfc8439_wolf_encrypt() {
    let key = GenericArray::from_slice(&RFC8439_KEY);
    let nonce = Nonce::<wolfcrypt::ChaCha20Poly1305>::from_slice(&RFC8439_NONCE);

    let cipher = <wolfcrypt::ChaCha20Poly1305 as KeyInit>::new(key);

    let mut buf = RFC8439_PT.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(nonce, &RFC8439_AAD, &mut buf)
        .expect("RFC 8439 Section 2.8.2: wolf encrypt must succeed");

    assert_eq!(
        buf.as_slice(),
        &RFC8439_CT,
        "RFC 8439 Section 2.8.2: wolf ciphertext does not match expected"
    );
    assert_eq!(
        tag.as_slice(),
        &RFC8439_TAG,
        "RFC 8439 Section 2.8.2: wolf authentication tag does not match expected"
    );
}

/// Wolf decryption must recover the original plaintext.
#[test]
fn rfc8439_wolf_decrypt() {
    let key = GenericArray::from_slice(&RFC8439_KEY);
    let nonce = Nonce::<wolfcrypt::ChaCha20Poly1305>::from_slice(&RFC8439_NONCE);
    let tag = GenericArray::from_slice(&RFC8439_TAG);

    let cipher = <wolfcrypt::ChaCha20Poly1305 as KeyInit>::new(key);

    let mut buf = RFC8439_CT.to_vec();
    cipher
        .decrypt_in_place_detached(nonce, &RFC8439_AAD, &mut buf, tag)
        .expect("RFC 8439 Section 2.8.2: wolf decrypt must succeed");

    assert_eq!(
        buf.as_slice(),
        &RFC8439_PT,
        "RFC 8439 Section 2.8.2: wolf decrypted plaintext does not match expected"
    );
}

/// Pure-Rust ChaCha20Poly1305 must produce the same ciphertext and tag (sanity check).
#[test]
fn rfc8439_pure_encrypt() {
    let key = GenericArray::from_slice(&RFC8439_KEY);
    let nonce =
        Nonce::<chacha20poly1305::ChaCha20Poly1305>::from_slice(&RFC8439_NONCE);

    let cipher = <chacha20poly1305::ChaCha20Poly1305 as KeyInit>::new(key);

    let mut buf = RFC8439_PT.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(nonce, &RFC8439_AAD, &mut buf)
        .expect("RFC 8439 Section 2.8.2: pure encrypt must succeed (sanity check)");

    assert_eq!(
        buf.as_slice(),
        &RFC8439_CT,
        "RFC 8439 Section 2.8.2: pure ciphertext must match RFC vector (sanity check)"
    );
    assert_eq!(
        tag.as_slice(),
        &RFC8439_TAG,
        "RFC 8439 Section 2.8.2: pure tag must match RFC vector (sanity check)"
    );
}

/// Wolf-encrypted data must be decryptable by pure-Rust implementation.
#[test]
fn rfc8439_wolf_encrypt_pure_decrypt() {
    let key = GenericArray::from_slice(&RFC8439_KEY);
    let nonce_wolf =
        Nonce::<wolfcrypt::ChaCha20Poly1305>::from_slice(&RFC8439_NONCE);
    let nonce_pure =
        Nonce::<chacha20poly1305::ChaCha20Poly1305>::from_slice(&RFC8439_NONCE);

    let wolf = <wolfcrypt::ChaCha20Poly1305 as KeyInit>::new(key);
    let pure = <chacha20poly1305::ChaCha20Poly1305 as KeyInit>::new(key);

    let mut ct = RFC8439_PT.to_vec();
    let tag = wolf
        .encrypt_in_place_detached(nonce_wolf, &RFC8439_AAD, &mut ct)
        .expect("RFC 8439: wolf encrypt must succeed");

    let mut recovered = ct.clone();
    pure.decrypt_in_place_detached(nonce_pure, &RFC8439_AAD, &mut recovered, &tag)
        .expect("RFC 8439: pure must decrypt wolf-encrypted data");

    assert_eq!(
        recovered.as_slice(),
        &RFC8439_PT,
        "RFC 8439: pure-decrypted plaintext must match original"
    );
}

/// Pure-encrypted data must be decryptable by wolf.
#[test]
fn rfc8439_pure_encrypt_wolf_decrypt() {
    let key = GenericArray::from_slice(&RFC8439_KEY);
    let nonce_wolf =
        Nonce::<wolfcrypt::ChaCha20Poly1305>::from_slice(&RFC8439_NONCE);
    let nonce_pure =
        Nonce::<chacha20poly1305::ChaCha20Poly1305>::from_slice(&RFC8439_NONCE);

    let wolf = <wolfcrypt::ChaCha20Poly1305 as KeyInit>::new(key);
    let pure = <chacha20poly1305::ChaCha20Poly1305 as KeyInit>::new(key);

    let mut ct = RFC8439_PT.to_vec();
    let tag = pure
        .encrypt_in_place_detached(nonce_pure, &RFC8439_AAD, &mut ct)
        .expect("RFC 8439: pure encrypt must succeed");

    let mut recovered = ct.clone();
    wolf.decrypt_in_place_detached(nonce_wolf, &RFC8439_AAD, &mut recovered, &tag)
        .expect("RFC 8439: wolf must decrypt pure-encrypted data");

    assert_eq!(
        recovered.as_slice(),
        &RFC8439_PT,
        "RFC 8439: wolf-decrypted plaintext must match original"
    );
}

/// Tampered ciphertext must be rejected by wolf.
#[test]
fn rfc8439_tampered_ct_rejected() {
    let key = GenericArray::from_slice(&RFC8439_KEY);
    let nonce = Nonce::<wolfcrypt::ChaCha20Poly1305>::from_slice(&RFC8439_NONCE);
    let tag = GenericArray::from_slice(&RFC8439_TAG);

    let cipher = <wolfcrypt::ChaCha20Poly1305 as KeyInit>::new(key);

    let mut bad_ct = RFC8439_CT.to_vec();
    bad_ct[0] ^= 0xff;

    let result = cipher.decrypt_in_place_detached(nonce, &RFC8439_AAD, &mut bad_ct, tag);
    assert!(
        result.is_err(),
        "RFC 8439: wolf must reject tampered ciphertext"
    );
}

/// Tampered tag must be rejected by wolf.
#[test]
fn rfc8439_tampered_tag_rejected() {
    let key = GenericArray::from_slice(&RFC8439_KEY);
    let nonce = Nonce::<wolfcrypt::ChaCha20Poly1305>::from_slice(&RFC8439_NONCE);

    let mut bad_tag_bytes = RFC8439_TAG;
    bad_tag_bytes[0] ^= 0xff;
    let bad_tag = GenericArray::from_slice(&bad_tag_bytes);

    let cipher = <wolfcrypt::ChaCha20Poly1305 as KeyInit>::new(key);

    let mut ct = RFC8439_CT.to_vec();
    let result = cipher.decrypt_in_place_detached(nonce, &RFC8439_AAD, &mut ct, bad_tag);
    assert!(
        result.is_err(),
        "RFC 8439: wolf must reject tampered authentication tag"
    );
}

/// Wrong AAD must be rejected by wolf.
#[test]
fn rfc8439_wrong_aad_rejected() {
    let key = GenericArray::from_slice(&RFC8439_KEY);
    let nonce = Nonce::<wolfcrypt::ChaCha20Poly1305>::from_slice(&RFC8439_NONCE);
    let tag = GenericArray::from_slice(&RFC8439_TAG);

    let cipher = <wolfcrypt::ChaCha20Poly1305 as KeyInit>::new(key);

    let mut ct = RFC8439_CT.to_vec();
    let wrong_aad = hex!("50515253c0c1c2c3c4c5c6c8"); // last byte changed
    let result = cipher.decrypt_in_place_detached(nonce, &wrong_aad, &mut ct, tag);
    assert!(
        result.is_err(),
        "RFC 8439: wolf must reject decryption with wrong AAD"
    );
}

/// Verify the plaintext is the ASCII string from the RFC.
#[test]
fn rfc8439_plaintext_is_sunscreen() {
    let expected = b"Ladies and Gentlemen of the class of '99: \
If I could offer you only one tip for the future, sunscreen would be it.";
    assert_eq!(
        &RFC8439_PT[..],
        &expected[..],
        "RFC 8439 Section 2.8.2: plaintext must be the 'sunscreen' message"
    );
}

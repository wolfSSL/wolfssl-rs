mod helpers;

use generic_array::GenericArray;
use helpers::random_bytes;
use rand::thread_rng;

/// Compute a Poly1305 tag using the wolfCrypt-backed implementation
/// (via the `digest::Mac` trait).  Accepts arbitrary-length input.
#[cfg(wolfssl_poly1305)]
fn wolf_poly1305_tag(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
    use digest::Mac;
    use wolfcrypt::WolfPoly1305;

    let mut mac =
        <WolfPoly1305 as Mac>::new_from_slice(key).expect("wolf: 32-byte key must be accepted");
    mac.update(data);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(tag.as_slice());
    out
}

/// Compute a Poly1305 tag using the pure-Rust implementation.
///
/// Uses `Poly1305::compute_unpadded` which handles arbitrary-length
/// input (including partial trailing blocks), matching the standard
/// Poly1305 algorithm from RFC 8439.
#[cfg(wolfssl_poly1305)]
fn pure_poly1305_tag(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
    use universal_hash::KeyInit;

    let ga_key = GenericArray::from_slice(key);
    let mac = poly1305::Poly1305::new(ga_key);
    let tag = mac.compute_unpadded(data);
    let mut out = [0u8; 16];
    out.copy_from_slice(tag.as_slice());
    out
}

/// Fixed 32-byte key and a single 16-byte message: tags must match.
#[test]
#[cfg(wolfssl_poly1305)]
fn fixed_key_message_equiv() {
    let key: [u8; 32] = [
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06,
        0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49,
        0xf5, 0x1b,
    ];
    // Exactly one 16-byte block.
    let msg: [u8; 16] = [
        0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x67, 0x72, 0x61, 0x70, 0x68, 0x69, 0x63, 0x20, 0x46,
        0x6f,
    ];

    let wolf_tag = wolf_poly1305_tag(&key, &msg);
    let pure_tag = pure_poly1305_tag(&key, &msg);

    assert_eq!(
        wolf_tag, pure_tag,
        "fixed key+message: wolf and pure-Rust Poly1305 tags must be identical"
    );
}

/// Random key and various message lengths including non-block-aligned.
#[test]
#[cfg(wolfssl_poly1305)]
fn random_equiv() {
    let mut rng = thread_rng();

    for &len in helpers::SYMMETRIC_LENGTHS {
        let key_bytes = random_bytes(&mut rng, 32);
        let key: [u8; 32] = key_bytes.try_into().unwrap();
        let msg = random_bytes(&mut rng, len);

        let wolf_tag = wolf_poly1305_tag(&key, &msg);
        let pure_tag = pure_poly1305_tag(&key, &msg);

        assert_eq!(
            wolf_tag, pure_tag,
            "random equiv: tags must match for {len}-byte message"
        );
    }
}

/// Partial-block messages (1, 7, 15, 17, 31, 33 bytes): tags must match.
#[test]
#[cfg(wolfssl_poly1305)]
fn partial_block_equiv() {
    let mut rng = thread_rng();

    for &len in &[1usize, 7, 15, 17, 31, 33] {
        let key_bytes = random_bytes(&mut rng, 32);
        let key: [u8; 32] = key_bytes.try_into().unwrap();
        let msg = random_bytes(&mut rng, len);

        let wolf_tag = wolf_poly1305_tag(&key, &msg);
        let pure_tag = pure_poly1305_tag(&key, &msg);

        assert_eq!(
            wolf_tag, pure_tag,
            "partial-block: tags must match for {len}-byte message"
        );
    }
}

/// Multi-block messages (various multiples of 16): tags must match.
#[test]
#[cfg(wolfssl_poly1305)]
fn multi_block_equiv() {
    let mut rng = thread_rng();

    for &len in helpers::BLOCK_ALIGNED_LENGTHS {
        let key_bytes = random_bytes(&mut rng, 32);
        let key: [u8; 32] = key_bytes.try_into().unwrap();
        let msg = random_bytes(&mut rng, len);

        let wolf_tag = wolf_poly1305_tag(&key, &msg);
        let pure_tag = pure_poly1305_tag(&key, &msg);

        assert_eq!(
            wolf_tag, pure_tag,
            "multi-block: tags must match for {len}-byte message"
        );
    }
}

/// Empty message: both implementations must agree.
#[test]
#[cfg(wolfssl_poly1305)]
fn empty_message_equiv() {
    let mut rng = thread_rng();
    let key_bytes = random_bytes(&mut rng, 32);
    let key: [u8; 32] = key_bytes.try_into().unwrap();

    let wolf_tag = wolf_poly1305_tag(&key, &[]);
    let pure_tag = pure_poly1305_tag(&key, &[]);

    assert_eq!(
        wolf_tag, pure_tag,
        "empty message: wolf and pure-Rust Poly1305 tags must match"
    );
}

/// Different keys on the same message must produce different tags.
#[test]
#[cfg(wolfssl_poly1305)]
fn canary_wrong_key() {
    let mut rng = thread_rng();
    let key_a_bytes = random_bytes(&mut rng, 32);
    let key_b_bytes = random_bytes(&mut rng, 32);
    let msg = random_bytes(&mut rng, 64);

    let key_a: [u8; 32] = key_a_bytes.try_into().unwrap();
    let key_b: [u8; 32] = key_b_bytes.try_into().unwrap();

    let tag_a = wolf_poly1305_tag(&key_a, &msg);
    let tag_b = wolf_poly1305_tag(&key_b, &msg);

    assert_ne!(
        tag_a, tag_b,
        "different keys must produce different Poly1305 tags"
    );
}

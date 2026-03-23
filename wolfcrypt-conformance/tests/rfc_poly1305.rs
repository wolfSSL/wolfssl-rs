#![cfg(wolfssl_poly1305)]

mod helpers;

use hex_literal::hex;

/// RFC 8439 Section 2.5.2 -- Poly1305 MAC test vector.
///
/// Key:     85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b
/// Message: "Cryptographic Forum Research Group"
/// Tag:     a8061dc1305136c6c22b8baf0c0127a9

const RFC8439_KEY: [u8; 32] =
    hex!("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
const RFC8439_MSG: [u8; 34] = hex!(
    "43727970746f6772617068696320466f"
    "72756d205265736561726368204772"
    "6f7570"
);
const RFC8439_TAG: [u8; 16] = hex!("a8061dc1305136c6c22b8baf0c0127a9");

/// Verify the message bytes are the ASCII encoding of the expected string.
#[test]
fn rfc8439_message_is_correct_ascii() {
    let expected = b"Cryptographic Forum Research Group";
    assert_eq!(
        &RFC8439_MSG[..],
        &expected[..],
        "RFC 8439 Section 2.5.2: message bytes must be ASCII 'Cryptographic Forum Research Group'"
    );
}

/// Wolf Poly1305 must produce the exact tag from the RFC.
#[test]
fn rfc8439_wolf_tag() {
    use digest::Mac;
    use wolfcrypt::WolfPoly1305;

    let mut mac = <WolfPoly1305 as Mac>::new_from_slice(&RFC8439_KEY)
        .expect("RFC 8439 Section 2.5.2: wolf must accept 32-byte Poly1305 key");
    mac.update(&RFC8439_MSG);
    let tag = mac.finalize().into_bytes();

    assert_eq!(
        tag.as_slice(),
        &RFC8439_TAG,
        "RFC 8439 Section 2.5.2: wolf Poly1305 tag does not match expected"
    );
}

/// Wolf Poly1305 verify_slice must accept the correct tag.
#[test]
fn rfc8439_wolf_verify() {
    use digest::Mac;
    use wolfcrypt::WolfPoly1305;

    let mut mac = <WolfPoly1305 as Mac>::new_from_slice(&RFC8439_KEY)
        .expect("RFC 8439 Section 2.5.2: wolf must accept 32-byte Poly1305 key");
    mac.update(&RFC8439_MSG);
    mac.verify_slice(&RFC8439_TAG)
        .expect("RFC 8439 Section 2.5.2: wolf Poly1305 verify must accept correct tag");
}

/// Wolf Poly1305 must reject a tampered tag.
#[test]
fn rfc8439_wolf_tampered_tag_rejected() {
    use digest::Mac;
    use wolfcrypt::WolfPoly1305;

    let mut bad_tag = RFC8439_TAG;
    bad_tag[0] ^= 0x01;

    let mut mac = <WolfPoly1305 as Mac>::new_from_slice(&RFC8439_KEY)
        .expect("RFC 8439 Section 2.5.2: wolf must accept 32-byte Poly1305 key");
    mac.update(&RFC8439_MSG);
    let result = mac.verify_slice(&bad_tag);
    assert!(
        result.is_err(),
        "RFC 8439 Section 2.5.2: wolf Poly1305 must reject tampered tag"
    );
}

/// Wolf Poly1305 must produce a different tag when the message is altered.
#[test]
fn rfc8439_wolf_tampered_message_different_tag() {
    use digest::Mac;
    use wolfcrypt::WolfPoly1305;

    let mut tampered_msg = RFC8439_MSG.to_vec();
    tampered_msg[0] ^= 0xff;

    let mut mac = <WolfPoly1305 as Mac>::new_from_slice(&RFC8439_KEY)
        .expect("RFC 8439 Section 2.5.2: wolf must accept 32-byte Poly1305 key");
    mac.update(&tampered_msg);
    let tag = mac.finalize().into_bytes();

    assert_ne!(
        tag.as_slice(),
        &RFC8439_TAG,
        "RFC 8439 Section 2.5.2: wolf Poly1305 tag must differ when message is altered"
    );
}

/// Wolf Poly1305 must produce a different tag with a different key.
#[test]
fn rfc8439_wolf_different_key_different_tag() {
    use digest::Mac;
    use wolfcrypt::WolfPoly1305;

    let mut other_key = RFC8439_KEY;
    other_key[0] ^= 0x01;

    let mut mac = <WolfPoly1305 as Mac>::new_from_slice(&other_key)
        .expect("wolf must accept modified 32-byte Poly1305 key");
    mac.update(&RFC8439_MSG);
    let tag = mac.finalize().into_bytes();

    assert_ne!(
        tag.as_slice(),
        &RFC8439_TAG,
        "RFC 8439 Section 2.5.2: wolf Poly1305 tag must differ with a different key"
    );
}

/// Incremental update must produce the same tag as a single update.
#[test]
fn rfc8439_wolf_incremental_update() {
    use digest::Mac;
    use wolfcrypt::WolfPoly1305;

    // Single update
    let mut mac_single = <WolfPoly1305 as Mac>::new_from_slice(&RFC8439_KEY)
        .expect("wolf must accept 32-byte Poly1305 key");
    mac_single.update(&RFC8439_MSG);
    let tag_single = mac_single.finalize().into_bytes();

    // Incremental: split message into two parts
    let (part1, part2) = RFC8439_MSG.split_at(17);
    let mut mac_inc = <WolfPoly1305 as Mac>::new_from_slice(&RFC8439_KEY)
        .expect("wolf must accept 32-byte Poly1305 key");
    mac_inc.update(part1);
    mac_inc.update(part2);
    let tag_inc = mac_inc.finalize().into_bytes();

    assert_eq!(
        tag_single.as_slice(),
        tag_inc.as_slice(),
        "RFC 8439 Section 2.5.2: incremental Poly1305 update must produce same tag as single update"
    );

    assert_eq!(
        tag_single.as_slice(),
        &RFC8439_TAG,
        "RFC 8439 Section 2.5.2: Poly1305 tag must match RFC vector regardless of update strategy"
    );
}

/// Byte-at-a-time update must still produce the correct tag.
#[test]
fn rfc8439_wolf_byte_at_a_time() {
    use digest::Mac;
    use wolfcrypt::WolfPoly1305;

    let mut mac = <WolfPoly1305 as Mac>::new_from_slice(&RFC8439_KEY)
        .expect("wolf must accept 32-byte Poly1305 key");
    for &b in RFC8439_MSG.iter() {
        mac.update(&[b]);
    }
    let tag = mac.finalize().into_bytes();

    assert_eq!(
        tag.as_slice(),
        &RFC8439_TAG,
        "RFC 8439 Section 2.5.2: byte-at-a-time Poly1305 must produce correct tag"
    );
}

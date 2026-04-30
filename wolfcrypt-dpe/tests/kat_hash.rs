//! Known Answer Tests for SHA-256 and SHA-384 hash operations.
//! Test vectors from NIST FIPS 180-4.

use caliptra_dpe_crypto::{Crypto, Digest, Hasher};
use wolfcrypt_dpe::{WolfCryptDpe, WolfCryptDpe256};

// ---------- SHA-256 ----------

#[test]
fn sha256_empty_message() {
    // NIST FIPS 180-4, Section B.1 (SHA-256, empty message)
    // Also: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf
    let expected =
        hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").unwrap();

    let mut dpe = WolfCryptDpe256::new_p256();
    let digest = dpe.hash(b"").unwrap();
    match &digest {
        Digest::Sha256(sha) => assert_eq!(&sha.0[..], &expected[..]),
        _ => panic!("Expected Sha256 variant"),
    }
}

#[test]
fn sha256_abc() {
    // NIST FIPS 180-4, Section B.1 (SHA-256, "abc")
    let expected =
        hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad").unwrap();

    let mut dpe = WolfCryptDpe256::new_p256();
    let digest = dpe.hash(b"abc").unwrap();
    match &digest {
        Digest::Sha256(sha) => assert_eq!(&sha.0[..], &expected[..]),
        _ => panic!("Expected Sha256 variant"),
    }
}

#[test]
fn sha256_448bit() {
    // NIST FIPS 180-4, Section B.2 (SHA-256, 448-bit message)
    // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    let expected =
        hex::decode("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1").unwrap();

    let mut dpe = WolfCryptDpe256::new_p256();
    let digest = dpe
        .hash(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
        .unwrap();
    match &digest {
        Digest::Sha256(sha) => assert_eq!(&sha.0[..], &expected[..]),
        _ => panic!("Expected Sha256 variant"),
    }
}

// ---------- SHA-384 ----------

#[test]
fn sha384_empty_message() {
    // NIST FIPS 180-4, Section D.1 (SHA-384, empty message)
    // Also: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA384.pdf
    let expected = hex::decode(
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
    )
    .unwrap();

    let mut dpe = WolfCryptDpe::new_p384();
    let digest = dpe.hash(b"").unwrap();
    match &digest {
        Digest::Sha384(sha) => assert_eq!(&sha.0[..], &expected[..]),
        _ => panic!("Expected Sha384 variant"),
    }
}

#[test]
fn sha384_abc() {
    // NIST FIPS 180-4, Section D.1 (SHA-384, "abc")
    let expected = hex::decode(
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
    )
    .unwrap();

    let mut dpe = WolfCryptDpe::new_p384();
    let digest = dpe.hash(b"abc").unwrap();
    match &digest {
        Digest::Sha384(sha) => assert_eq!(&sha.0[..], &expected[..]),
        _ => panic!("Expected Sha384 variant"),
    }
}

#[test]
fn sha384_896bit() {
    // NIST FIPS 180-4, Section D.3 (SHA-384, 896-bit message)
    let expected = hex::decode(
        "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039",
    )
    .unwrap();

    let mut dpe = WolfCryptDpe::new_p384();
    let digest = dpe
        .hash(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")
        .unwrap();
    match &digest {
        Digest::Sha384(sha) => assert_eq!(&sha.0[..], &expected[..]),
        _ => panic!("Expected Sha384 variant"),
    }
}

// ---------- Incremental hash ----------

#[test]
fn sha384_incremental_matches_oneshot() {
    // Incremental hash (hash_initialize + update + finish) must match one-shot hash
    let data = b"The quick brown fox jumps over the lazy dog";
    let mut dpe = WolfCryptDpe::new_p384();

    let oneshot = dpe.hash(data).unwrap();

    let mut hasher = dpe.hash_initialize().unwrap();
    hasher.update(&data[..10]).unwrap();
    hasher.update(&data[10..]).unwrap();
    let incremental = hasher.finish().unwrap();

    assert_eq!(oneshot.as_slice(), incremental.as_slice());
}

#[test]
fn sha256_incremental_matches_oneshot() {
    let data = b"The quick brown fox jumps over the lazy dog";
    let mut dpe = WolfCryptDpe256::new_p256();

    let oneshot = dpe.hash(data).unwrap();

    let mut hasher = dpe.hash_initialize().unwrap();
    hasher.update(&data[..20]).unwrap();
    hasher.update(&data[20..]).unwrap();
    let incremental = hasher.finish().unwrap();

    assert_eq!(oneshot.as_slice(), incremental.as_slice());
}

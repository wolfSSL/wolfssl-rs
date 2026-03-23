#![cfg(wolfssl_hkdf)]

mod helpers;

use hex_literal::hex;
use wolfcrypt::WolfHkdfSha256;

/// RFC 5869 Appendix A -- HKDF test vectors (SHA-256 only).
///
/// Each vector specifies IKM, salt, info, L (output length), expected PRK,
/// and expected OKM.
struct HkdfVector {
    name: &'static str,
    ikm: &'static [u8],
    salt: &'static [u8],
    info: &'static [u8],
    l: usize,
    prk: &'static [u8],
    okm: &'static [u8],
}

// --- Test Case 1: Basic (SHA-256) ---
const TC1_IKM: [u8; 22] = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
const TC1_SALT: [u8; 13] = hex!("000102030405060708090a0b0c");
const TC1_INFO: [u8; 10] = hex!("f0f1f2f3f4f5f6f7f8f9");
const TC1_PRK: [u8; 32] =
    hex!("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
const TC1_OKM: [u8; 42] = hex!(
    "3cb25f25faacd57a90434f64d0362f2a"
    "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
    "34007208d5b887185865"
);

// --- Test Case 2: Longer inputs (SHA-256) ---
const TC2_IKM: [u8; 80] = hex!(
    "000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f"
    "202122232425262728292a2b2c2d2e2f"
    "303132333435363738393a3b3c3d3e3f"
    "404142434445464748494a4b4c4d4e4f"
);
const TC2_SALT: [u8; 80] = hex!(
    "606162636465666768696a6b6c6d6e6f"
    "707172737475767778797a7b7c7d7e7f"
    "808182838485868788898a8b8c8d8e8f"
    "909192939495969798999a9b9c9d9e9f"
    "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
);
const TC2_INFO: [u8; 80] = hex!(
    "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
    "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
    "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
    "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
    "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
);
const TC2_PRK: [u8; 32] =
    hex!("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244");
const TC2_OKM: [u8; 82] = hex!(
    "b11e398dc80327a1c8e7f78c596a4934"
    "4f012eda2d4efad8a050cc4c19afa97c"
    "59045a99cac7827271cb41c65e590e09"
    "da3275600c2f09b8367793a9aca3db71"
    "cc30c58179ec3e87c14c01d5c1f3434f"
    "1d87"
);

// --- Test Case 3: Zero-length salt and info (SHA-256) ---
const TC3_IKM: [u8; 22] = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
const TC3_PRK: [u8; 32] =
    hex!("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04");
const TC3_OKM: [u8; 42] = hex!(
    "8da4e775a563c18f715f802a063c5a31"
    "b8a11f5c5ee1879ec3454e5f3c738d2d"
    "9d201395faa4b61a96c8"
);

fn vectors() -> Vec<HkdfVector> {
    vec![
        HkdfVector {
            name: "RFC 5869 Test Case 1 (SHA-256, basic)",
            ikm: &TC1_IKM,
            salt: &TC1_SALT,
            info: &TC1_INFO,
            l: 42,
            prk: &TC1_PRK,
            okm: &TC1_OKM,
        },
        HkdfVector {
            name: "RFC 5869 Test Case 2 (SHA-256, longer inputs)",
            ikm: &TC2_IKM,
            salt: &TC2_SALT,
            info: &TC2_INFO,
            l: 82,
            prk: &TC2_PRK,
            okm: &TC2_OKM,
        },
        HkdfVector {
            name: "RFC 5869 Test Case 3 (SHA-256, zero-length salt and info)",
            ikm: &TC3_IKM,
            salt: &[],
            info: &[],
            l: 42,
            prk: &TC3_PRK,
            okm: &TC3_OKM,
        },
    ]
}

/// Wolf extract must produce the correct PRK for each RFC vector.
#[test]
fn rfc5869_wolf_extract_prk() {
    for v in vectors() {
        let salt_opt = if v.salt.is_empty() {
            None
        } else {
            Some(v.salt)
        };
        let (prk, _hkdf) = WolfHkdfSha256::extract(salt_opt, v.ikm);
        assert_eq!(
            prk.as_slice(),
            v.prk,
            "{}: wolf PRK mismatch",
            v.name
        );
    }
}

/// Wolf expand must produce the correct OKM for each RFC vector.
#[test]
fn rfc5869_wolf_expand_okm() {
    for v in vectors() {
        let salt_opt = if v.salt.is_empty() {
            None
        } else {
            Some(v.salt)
        };
        let (_prk, hkdf) = WolfHkdfSha256::extract(salt_opt, v.ikm);
        let mut okm = vec![0u8; v.l];
        hkdf.expand(v.info, &mut okm)
            .unwrap_or_else(|e| panic!("{}: wolf expand failed: {e}", v.name));
        assert_eq!(
            &okm,
            v.okm,
            "{}: wolf OKM mismatch",
            v.name
        );
    }
}

/// Pure-Rust HKDF must produce the same PRK (sanity check on the vectors).
#[test]
fn rfc5869_pure_extract_prk() {
    for v in vectors() {
        let salt_opt = if v.salt.is_empty() {
            None
        } else {
            Some(v.salt)
        };
        let (prk, _hkdf) = hkdf::Hkdf::<sha2::Sha256>::extract(salt_opt, v.ikm);
        assert_eq!(
            prk.as_slice(),
            v.prk,
            "{}: pure PRK mismatch (vector sanity check)",
            v.name
        );
    }
}

/// Pure-Rust HKDF must produce the same OKM (sanity check on the vectors).
#[test]
fn rfc5869_pure_expand_okm() {
    for v in vectors() {
        let salt_opt = if v.salt.is_empty() {
            None
        } else {
            Some(v.salt)
        };
        let (_prk, hkdf) = hkdf::Hkdf::<sha2::Sha256>::extract(salt_opt, v.ikm);
        let mut okm = vec![0u8; v.l];
        hkdf.expand(v.info, &mut okm)
            .unwrap_or_else(|e| panic!("{}: pure expand failed: {e}", v.name));
        assert_eq!(
            &okm,
            v.okm,
            "{}: pure OKM mismatch (vector sanity check)",
            v.name
        );
    }
}

/// Wolf and pure-Rust must produce identical PRK and OKM for all vectors.
#[test]
fn rfc5869_wolf_matches_pure() {
    for v in vectors() {
        let salt_opt = if v.salt.is_empty() {
            None
        } else {
            Some(v.salt)
        };

        let (wolf_prk, wolf_hkdf) = WolfHkdfSha256::extract(salt_opt, v.ikm);
        let (pure_prk, pure_hkdf) = hkdf::Hkdf::<sha2::Sha256>::extract(salt_opt, v.ikm);

        assert_eq!(
            wolf_prk.as_slice(),
            pure_prk.as_slice(),
            "{}: wolf and pure PRK must be identical",
            v.name
        );

        let mut wolf_okm = vec![0u8; v.l];
        let mut pure_okm = vec![0u8; v.l];
        wolf_hkdf
            .expand(v.info, &mut wolf_okm)
            .unwrap_or_else(|e| panic!("{}: wolf expand failed: {e}", v.name));
        pure_hkdf
            .expand(v.info, &mut pure_okm)
            .unwrap_or_else(|e| panic!("{}: pure expand failed: {e}", v.name));

        assert_eq!(
            wolf_okm, pure_okm,
            "{}: wolf and pure OKM must be identical",
            v.name
        );
    }
}

/// Full extract-then-expand pipeline via the `new` constructor.
#[test]
fn rfc5869_new_constructor() {
    for v in vectors() {
        let salt_opt = if v.salt.is_empty() {
            None
        } else {
            Some(v.salt)
        };

        let wolf_hkdf = WolfHkdfSha256::new(salt_opt, v.ikm);
        let mut okm = vec![0u8; v.l];
        wolf_hkdf
            .expand(v.info, &mut okm)
            .unwrap_or_else(|e| panic!("{}: wolf new+expand failed: {e}", v.name));
        assert_eq!(
            &okm,
            v.okm,
            "{}: OKM from new() constructor must match RFC vector",
            v.name
        );
    }
}

/// Reconstruct from PRK bytes and expand -- must still produce correct OKM.
#[test]
fn rfc5869_from_prk() {
    for v in vectors() {
        let wolf_hkdf = WolfHkdfSha256::from_prk(v.prk)
            .unwrap_or_else(|e| panic!("{}: wolf from_prk failed: {e}", v.name));
        let mut okm = vec![0u8; v.l];
        wolf_hkdf
            .expand(v.info, &mut okm)
            .unwrap_or_else(|e| panic!("{}: wolf from_prk+expand failed: {e}", v.name));
        assert_eq!(
            &okm,
            v.okm,
            "{}: OKM from from_prk() must match RFC vector",
            v.name
        );
    }
}

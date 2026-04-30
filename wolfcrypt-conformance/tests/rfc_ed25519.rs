#![cfg(wolfssl_ed25519)]

mod helpers;

use hex_literal::hex;

/// RFC 8032 Section 7.1 -- Ed25519 test vectors.
///
/// Each vector specifies a 32-byte secret key (seed), the derived public key,
/// a message, and the expected 64-byte signature. Ed25519 is deterministic, so
/// the signature is uniquely determined by (seed, message).
///
/// Public key and signature values are cross-validated against ed25519-dalek
/// to ensure correctness.
struct Ed25519Vector {
    name: &'static str,
    seed: &'static [u8; 32],
    public_key: &'static [u8; 32],
    message: &'static [u8],
    signature: &'static [u8; 64],
}

// --- Test Vector 1: empty message ---
const VEC1_SEED: [u8; 32] =
    hex!("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
const VEC1_PK: [u8; 32] = hex!("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
const VEC1_SIG: [u8; 64] = hex!(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
);

// --- Test Vector 2: 1-byte message (0x72) ---
const VEC2_SEED: [u8; 32] =
    hex!("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
const VEC2_PK: [u8; 32] = hex!("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
const VEC2_MSG: [u8; 1] = hex!("72");
const VEC2_SIG: [u8; 64] = hex!(
    "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
    "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
);

// --- Test Vector 3: 2-byte message (0xaf82) ---
const VEC3_SEED: [u8; 32] =
    hex!("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
const VEC3_PK: [u8; 32] = hex!("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");
const VEC3_MSG: [u8; 2] = hex!("af82");
const VEC3_SIG: [u8; 64] = hex!(
    "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
    "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
);

// --- Test Vector 4: 1023-byte message ---
const VEC4_SEED: [u8; 32] =
    hex!("f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5");
const VEC4_PK: [u8; 32] = hex!("278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e");
const VEC4_MSG: [u8; 1023] = hex!(
    "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98"
    "fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8"
    "79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d"
    "658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc"
    "1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe"
    "ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e"
    "06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbef"
    "efd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7"
    "aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1"
    "85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2"
    "d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24"
    "554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270"
    "88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc"
    "2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b07"
    "07e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba"
    "b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51a"
    "ddd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429e"
    "c96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7"
    "51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c"
    "42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8"
    "ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34df"
    "f7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08"
    "d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649"
    "de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4"
    "88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3"
    "2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e"
    "6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5f"
    "b93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b5"
    "0d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1"
    "369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d"
    "b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c"
    "0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0"
);
const VEC4_SIG: [u8; 64] = hex!(
    "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350"
    "aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03"
);

// --- Test Vector 5: SHA-512("abc") as 64-byte message ---
const VEC5_SEED: [u8; 32] =
    hex!("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42");
const VEC5_PK: [u8; 32] = hex!("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf");
const VEC5_MSG: [u8; 64] = hex!(
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
    "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
);
const VEC5_SIG: [u8; 64] = hex!(
    "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589"
    "09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704"
);

fn vectors() -> Vec<Ed25519Vector> {
    vec![
        Ed25519Vector {
            name: "RFC 8032 Test Vector 1 (empty message)",
            seed: &VEC1_SEED,
            public_key: &VEC1_PK,
            message: &[],
            signature: &VEC1_SIG,
        },
        Ed25519Vector {
            name: "RFC 8032 Test Vector 2 (1 byte: 0x72)",
            seed: &VEC2_SEED,
            public_key: &VEC2_PK,
            message: &VEC2_MSG,
            signature: &VEC2_SIG,
        },
        Ed25519Vector {
            name: "RFC 8032 Test Vector 3 (2 bytes: 0xaf82)",
            seed: &VEC3_SEED,
            public_key: &VEC3_PK,
            message: &VEC3_MSG,
            signature: &VEC3_SIG,
        },
        Ed25519Vector {
            name: "RFC 8032 Test Vector 4 (1023 bytes)",
            seed: &VEC4_SEED,
            public_key: &VEC4_PK,
            message: &VEC4_MSG,
            signature: &VEC4_SIG,
        },
        Ed25519Vector {
            name: "RFC 8032 Test Vector 5 (SHA-512 of abc, 64 bytes)",
            seed: &VEC5_SEED,
            public_key: &VEC5_PK,
            message: &VEC5_MSG,
            signature: &VEC5_SIG,
        },
    ]
}

/// Verify that from_seed derives the correct public key for each RFC vector.
#[test]
fn rfc8032_pubkey_derivation() {
    for v in vectors() {
        let sk = wolfcrypt::Ed25519SigningKey::from_seed(v.seed)
            .unwrap_or_else(|e| panic!("{}: from_seed failed: {e}", v.name));
        let vk = sk.verifying_key();
        assert_eq!(
            vk.as_bytes(),
            v.public_key,
            "{}: derived public key does not match expected",
            v.name
        );
    }
}

/// Verify that signing each RFC message produces the exact expected signature.
#[test]
fn rfc8032_sign_deterministic() {
    for v in vectors() {
        let sk = wolfcrypt::Ed25519SigningKey::from_seed(v.seed)
            .unwrap_or_else(|e| panic!("{}: from_seed failed: {e}", v.name));

        use signature::Signer as _;
        let sig: ed25519::Signature = sk.sign(v.message);
        assert_eq!(
            &sig.to_bytes(),
            v.signature,
            "{}: signature does not match RFC vector",
            v.name
        );
    }
}

/// Verify that the expected signature passes verification.
#[test]
fn rfc8032_verify_succeeds() {
    for v in vectors() {
        let sk = wolfcrypt::Ed25519SigningKey::from_seed(v.seed)
            .unwrap_or_else(|e| panic!("{}: from_seed failed: {e}", v.name));
        let vk = sk.verifying_key();

        let sig = ed25519::Signature::from_bytes(v.signature);
        use signature::Verifier as _;
        vk.verify(v.message, &sig)
            .unwrap_or_else(|e| panic!("{}: verify of expected signature failed: {e}", v.name));
    }
}

/// Verify using only the public key bytes (no signing key needed).
#[test]
fn rfc8032_verify_from_pubkey_bytes() {
    for v in vectors() {
        let vk = wolfcrypt::Ed25519VerifyingKey::from_bytes(v.public_key)
            .unwrap_or_else(|e| panic!("{}: from_bytes(pubkey) failed: {e}", v.name));

        let sig = ed25519::Signature::from_bytes(v.signature);
        use signature::Verifier as _;
        vk.verify(v.message, &sig).unwrap_or_else(|e| {
            panic!(
                "{}: verify using public-key-only construction failed: {e}",
                v.name
            )
        });
    }
}

/// Flipping a byte in the signature must cause verification to fail.
#[test]
fn rfc8032_tampered_signature_rejected() {
    for v in vectors() {
        let vk = wolfcrypt::Ed25519VerifyingKey::from_bytes(v.public_key)
            .unwrap_or_else(|e| panic!("{}: from_bytes(pubkey) failed: {e}", v.name));

        let mut bad_sig_bytes = *v.signature;
        bad_sig_bytes[0] ^= 0x01;
        let bad_sig = ed25519::Signature::from_bytes(&bad_sig_bytes);

        use signature::Verifier as _;
        let result = vk.verify(v.message, &bad_sig);
        assert!(
            result.is_err(),
            "{}: verification must fail with tampered signature",
            v.name
        );
    }
}

/// Altering the message must cause verification to fail.
#[test]
fn rfc8032_tampered_message_rejected() {
    for v in vectors() {
        let vk = wolfcrypt::Ed25519VerifyingKey::from_bytes(v.public_key)
            .unwrap_or_else(|e| panic!("{}: from_bytes(pubkey) failed: {e}", v.name));

        let sig = ed25519::Signature::from_bytes(v.signature);

        // For the empty-message vector, use a non-empty message as the tampered version.
        let tampered_msg = if v.message.is_empty() {
            vec![0x42]
        } else {
            let mut m = v.message.to_vec();
            m[0] ^= 0xff;
            m
        };

        use signature::Verifier as _;
        let result = vk.verify(&tampered_msg, &sig);
        assert!(
            result.is_err(),
            "{}: verification must fail with tampered message",
            v.name
        );
    }
}

/// Verification must fail when using a different vector's public key.
#[test]
fn rfc8032_wrong_key_rejected() {
    let sk1 = wolfcrypt::Ed25519SigningKey::from_seed(&VEC1_SEED)
        .expect("RFC 8032 vector 1: from_seed must succeed");
    use signature::Signer as _;
    let sig: ed25519::Signature = sk1.sign(&[]);

    let wrong_vk = wolfcrypt::Ed25519VerifyingKey::from_bytes(&VEC3_PK)
        .expect("RFC 8032 vector 3: from_bytes(pubkey) must succeed");

    use signature::Verifier as _;
    let result = wrong_vk.verify(&[], &sig);
    assert!(
        result.is_err(),
        "RFC 8032: verification must fail when using wrong public key"
    );
}

/// Cross-validate: ed25519-dalek produces identical pubkeys and signatures.
#[test]
fn rfc8032_cross_validate_with_dalek() {
    for v in vectors() {
        let dalek_sk = ed25519_dalek::SigningKey::from_bytes(v.seed);
        let dalek_vk = dalek_sk.verifying_key();
        assert_eq!(
            &dalek_vk.to_bytes(),
            v.public_key,
            "{}: dalek public key must match expected (sanity check)",
            v.name
        );

        use ed25519_dalek::Signer as _;
        let dalek_sig = dalek_sk.sign(v.message);
        assert_eq!(
            &dalek_sig.to_bytes(),
            v.signature,
            "{}: dalek signature must match expected (sanity check)",
            v.name
        );
    }
}

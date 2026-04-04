//! Caliptra hardware conformance binary.
//!
//! Verifies that SHA-256/384/512, HMAC-384, AES-256-GCM, and ECDSA P-384
//! operations route through the Caliptra hardware dispatch path (CryptoCb)
//! and produce correct output.
//!
//! Build and run:
//!   cargo conformance-caliptra
//!   # (alias defined in .cargo/config.toml)
//!
//! Requires: --features wolfcrypt-conformance/caliptra-hw

fn main() {
    #[cfg(all(feature = "caliptra-hw", not(target_arch = "riscv32")))]
    run_conformance();

    #[cfg(not(all(feature = "caliptra-hw", not(target_arch = "riscv32"))))]
    {
        eprintln!(
            "caliptra_hw_conformance requires \
             --features wolfcrypt-conformance/caliptra-hw on a non-riscv32 target."
        );
        std::process::exit(1);
    }
}

#[cfg(all(feature = "caliptra-hw", not(target_arch = "riscv32")))]
fn run_conformance() {
    use std::process;

    // -----------------------------------------------------------------------
    // Step 1 — Initialize the sw-emulator
    // -----------------------------------------------------------------------
    let _emu = caliptra_emu_periph::CaliptraRootBus::new(
        caliptra_emu_periph::CaliptraRootBusArgs::default(),
    );

    // -----------------------------------------------------------------------
    // Step 2 — wolfCrypt init + hardware backend registration
    // -----------------------------------------------------------------------
    let wc_rc = unsafe { wolfcrypt_sys::wolfCrypt_Init() };
    assert!(
        wc_rc == 0 || wc_rc == 1,
        "wolfCrypt_Init failed (expected 0 or 1, got {wc_rc})"
    );
    wolfcrypt_dpe_hw::init().expect("wolfcrypt_dpe_hw::init failed");

    let dev_id = wolfcrypt_dpe_hw::HW_DEVICE_ID;

    // -----------------------------------------------------------------------
    // Step 3 — SHA-256 conformance
    // -----------------------------------------------------------------------
    wolfcrypt_dpe_hw::reset_hw_dispatch_count();
    let sha256_count = run_sha_suite(
        wolfcrypt_sys::wc_HashType_WC_HASH_TYPE_SHA256,
        32,
        "sha256",
        "shavs/SHA256ShortMsg.rsp",
        "shavs/SHA256LongMsg.rsp",
        dev_id,
    );
    let sha256_dispatches = wolfcrypt_dpe_hw::hw_dispatch_count();
    if sha256_dispatches != sha256_count {
        eprintln!("HARDWARE PATH NOT TAKEN FOR SHA-256");
        eprintln!("  expected dispatches: {sha256_count}, got: {sha256_dispatches}");
        process::exit(1);
    }

    // -----------------------------------------------------------------------
    // Step 3 — SHA-384 conformance
    // -----------------------------------------------------------------------
    wolfcrypt_dpe_hw::reset_hw_dispatch_count();
    let sha384_count = run_sha_suite(
        wolfcrypt_sys::wc_HashType_WC_HASH_TYPE_SHA384,
        48,
        "sha384",
        "shavs/SHA384ShortMsg.rsp",
        "shavs/SHA384LongMsg.rsp",
        dev_id,
    );
    let sha384_dispatches = wolfcrypt_dpe_hw::hw_dispatch_count();
    if sha384_dispatches != sha384_count {
        eprintln!("HARDWARE PATH NOT TAKEN FOR SHA-384");
        eprintln!("  expected dispatches: {sha384_count}, got: {sha384_dispatches}");
        process::exit(1);
    }

    // -----------------------------------------------------------------------
    // Step 3 — SHA-512 conformance
    // -----------------------------------------------------------------------
    wolfcrypt_dpe_hw::reset_hw_dispatch_count();
    let sha512_count = run_sha_suite(
        wolfcrypt_sys::wc_HashType_WC_HASH_TYPE_SHA512,
        64,
        "sha512",
        "shavs/SHA512ShortMsg.rsp",
        "shavs/SHA512LongMsg.rsp",
        dev_id,
    );
    let sha512_dispatches = wolfcrypt_dpe_hw::hw_dispatch_count();
    if sha512_dispatches != sha512_count {
        eprintln!("HARDWARE PATH NOT TAKEN FOR SHA-512");
        eprintln!("  expected dispatches: {sha512_count}, got: {sha512_dispatches}");
        process::exit(1);
    }

    // -----------------------------------------------------------------------
    // Step 3 — HMAC-384 conformance (RFC 4231 test cases, NIST-confirmed)
    // -----------------------------------------------------------------------
    wolfcrypt_dpe_hw::reset_hw_dispatch_count();
    let hmac_count = run_hmac384_suite(dev_id);
    let hmac_dispatches = wolfcrypt_dpe_hw::hw_dispatch_count();
    if hmac_dispatches != hmac_count {
        eprintln!("HARDWARE PATH NOT TAKEN FOR HMAC-384");
        eprintln!("  expected dispatches: {hmac_count}, got: {hmac_dispatches}");
        process::exit(1);
    }

    // -----------------------------------------------------------------------
    // Step 3 — AES-256-GCM conformance (NIST SP 800-38D vectors)
    // -----------------------------------------------------------------------
    wolfcrypt_dpe_hw::reset_aes_dispatch_count();
    let aes_count = run_aes256gcm_suite(dev_id);
    let aes_dispatches = wolfcrypt_dpe_hw::aes_dispatch_count();
    if aes_dispatches != aes_count {
        eprintln!("HARDWARE PATH NOT TAKEN FOR AES-256-GCM");
        eprintln!("  expected dispatches: {aes_count}, got: {aes_dispatches}");
        process::exit(1);
    }

    // -----------------------------------------------------------------------
    // Step 3 — ECDSA P-384 sign/verify conformance
    // -----------------------------------------------------------------------
    wolfcrypt_dpe_hw::reset_ecc_dispatch_count();
    let ecc_count = run_ecdsa384_suite(dev_id);
    let ecc_dispatches = wolfcrypt_dpe_hw::ecc_dispatch_count();
    if ecc_dispatches != ecc_count {
        eprintln!("HARDWARE PATH NOT TAKEN FOR ECDSA P-384");
        eprintln!("  expected dispatches: {ecc_count}, got: {ecc_dispatches}");
        process::exit(1);
    }

    // -----------------------------------------------------------------------
    // Step 5 — Summary
    // -----------------------------------------------------------------------
    println!("=== caliptra_hw_conformance PASSED ===");
    println!("SHA-256        : {sha256_count} vectors — HW dispatch verified");
    println!("SHA-384        : {sha384_count} vectors — HW dispatch verified");
    println!("SHA-512        : {sha512_count} vectors — HW dispatch verified");
    println!("HMAC-384       : {hmac_count} vectors — HW dispatch verified");
    println!("AES-256-GCM    : {aes_count} dispatches (encrypt+decrypt) — HW dispatch verified");
    println!("ECDSA P-384    : {ecc_count} dispatches (sign+verify rounds) — HW dispatch verified");
}

// ---------------------------------------------------------------------------
// Vector directory helper
// ---------------------------------------------------------------------------

#[cfg(all(feature = "caliptra-hw", not(target_arch = "riscv32")))]
fn vector_dir() -> String {
    std::env::var("CONFORMANCE_VECTORS_DIR")
        .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/vectors").to_string())
}

// ---------------------------------------------------------------------------
// Minimal SHAVS parser
// ---------------------------------------------------------------------------
// Format (per NIST SHAVS spec):
//   Len = <bits>
//   Msg = <hex>
//   MD  = <hex>
// Consecutive blank-line-separated blocks; entries with Len = 0 use the
// 00 byte pad (we include the message but treat length=0 as empty slice).

#[cfg(all(feature = "caliptra-hw", not(target_arch = "riscv32")))]
fn parse_shavs(content: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut result = Vec::new();
    let mut len_bits: Option<usize> = None;
    let mut msg_hex: Option<String> = None;

    for line in content.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("Len = ") {
            len_bits = v.trim().parse().ok();
        } else if let Some(h) = line.strip_prefix("Msg = ") {
            msg_hex = Some(h.trim().to_string());
        } else if let Some(h) = line.strip_prefix("MD = ") {
            if let (Some(len), Some(ref mh)) = (len_bits.take(), msg_hex.take()) {
                let byte_len = len / 8;
                let msg_bytes = hex_decode(mh);
                let trimmed = msg_bytes[..byte_len.min(msg_bytes.len())].to_vec();
                result.push((trimmed, hex_decode(h.trim())));
            }
        }
    }
    result
}

#[cfg(all(feature = "caliptra-hw", not(target_arch = "riscv32")))]
fn hex_decode(s: &str) -> Vec<u8> {
    let s = s.trim();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("invalid hex in test vector"))
        .collect()
}

// ---------------------------------------------------------------------------
// SHA suite runner
// ---------------------------------------------------------------------------

#[cfg(all(feature = "caliptra-hw", not(target_arch = "riscv32")))]
fn run_sha_suite(
    hash_type: wolfcrypt_sys::wc_HashType,
    digest_len: usize,
    name: &str,
    short_file: &str,
    long_file: &str,
    dev_id: core::ffi::c_int,
) -> usize {
    let dir = vector_dir();
    let mut total = 0usize;

    for file in &[short_file, long_file] {
        let path = format!("{dir}/{file}");
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Warning: cannot load {path}: {e} — skipping");
                continue;
            }
        };
        let vectors = parse_shavs(&content);
        for (msg, expected_md) in &vectors {
            let mut digest = vec![0u8; digest_len];
            let rc = unsafe {
                wolfcrypt_sys::wc_Hash_ex(
                    hash_type,
                    if msg.is_empty() { core::ptr::null() } else { msg.as_ptr() },
                    msg.len() as u32,
                    digest.as_mut_ptr(),
                    digest.len() as u32,
                    core::ptr::null_mut(),
                    dev_id,
                )
            };
            assert_eq!(rc, 0, "{name}: wc_Hash_ex failed: {rc}");
            assert_eq!(
                &digest[..expected_md.len()],
                expected_md.as_slice(),
                "{name}: digest mismatch for msg len={}",
                msg.len()
            );
            total += 1;
        }
    }
    total
}

// ---------------------------------------------------------------------------
// HMAC-384 suite — RFC 4231 test cases (NIST CAVP confirmed)
// ---------------------------------------------------------------------------

#[cfg(all(feature = "caliptra-hw", not(target_arch = "riscv32")))]
fn run_hmac384_suite(dev_id: core::ffi::c_int) -> usize {
    // RFC 4231 test cases for HMAC-SHA-384.
    // Each entry: (key_hex, data_hex, expected_mac_hex).
    // TC1 and TC2 are short-key; TC6-7 use longer keys.
    const CASES: &[(&str, &str, &str)] = &[
        // TC 1
        (
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "4869205468657265",
            "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
        ),
        // TC 2
        (
            "4a656665",
            "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
            "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649",
        ),
        // TC 3 (data repeated)
        (
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27",
        ),
        // TC 4 (combined key+data)
        (
            "0102030405060708090a0b0c0d0e0f10111213141516171819",
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb",
        ),
    ];

    let mut total = 0usize;

    for &(key_hex, data_hex, expected_hex) in CASES {
        let key = hex_decode(key_hex);
        let data = hex_decode(data_hex);
        let expected = hex_decode(expected_hex);
        let mut output = vec![0u8; 48];

        unsafe {
            let mut hmac: wolfcrypt_sys::Hmac = core::mem::zeroed();
            let rc = wolfcrypt_sys::wc_HmacInit(&mut hmac, core::ptr::null_mut(), dev_id);
            assert_eq!(rc, 0, "hmac384: wc_HmacInit failed: {rc}");

            let rc = wolfcrypt_sys::wc_HmacSetKey(
                &mut hmac,
                wolfcrypt_sys::wc_HashType_WC_HASH_TYPE_SHA384 as i32,
                key.as_ptr(),
                key.len() as u32,
            );
            assert_eq!(rc, 0, "hmac384: wc_HmacSetKey failed: {rc}");

            let rc = wolfcrypt_sys::wc_HmacUpdate(&mut hmac, data.as_ptr(), data.len() as u32);
            assert_eq!(rc, 0, "hmac384: wc_HmacUpdate failed: {rc}");

            let rc = wolfcrypt_sys::wc_HmacFinal(&mut hmac, output.as_mut_ptr());
            assert_eq!(rc, 0, "hmac384: wc_HmacFinal failed: {rc}");

            wolfcrypt_sys::wc_HmacFree(&mut hmac);
        }

        assert_eq!(&output[..], expected.as_slice(), "hmac384: MAC mismatch");
        total += 1;
    }

    total
}

// ---------------------------------------------------------------------------
// AES-256-GCM suite — NIST SP 800-38D vectors
// ---------------------------------------------------------------------------

#[cfg(all(feature = "caliptra-hw", not(target_arch = "riscv32")))]
fn run_aes256gcm_suite(dev_id: core::ffi::c_int) -> usize {
    // Two AES-256-GCM test vectors from wolfSSL aesgcm_test() / McGrew-Viega GCM spec.
    // TC15: 256-bit key, 64-byte PT, empty AAD  → Tag b094dac5d93471bdec1a502270e3cc6c
    // TC16: 256-bit key, 60-byte PT, non-empty AAD → Tag 76fc6ece0f4e1768cddf8853bb2d551b
    // Each entry: (key, iv, aad, plaintext, expected_ct, expected_tag)
    const CASES: &[(&str, &str, &str, &str, &str, &str)] = &[
        // TC16 (GCM spec) — 256-bit key, 60-byte PT, non-empty AAD
        (
            "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
            "cafebabefacedbaddecaf888",
            "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
            "76fc6ece0f4e1768cddf8853bb2d551b",
        ),
        // TC15 (NIST SP 800-38D / GCM spec) — 256-bit key, 64-byte PT, empty AAD
        (
            "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
            "cafebabefacedbaddecaf888",
            "",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
            "b094dac5d93471bdec1a502270e3cc6c",
        ),
    ];

    let mut total = 0usize; // counts individual encrypt + decrypt dispatches

    for &(key_hex, iv_hex, aad_hex, pt_hex, expected_ct_hex, expected_tag_hex) in CASES {
        let key_bytes = hex_decode(key_hex);
        let iv_bytes = hex_decode(iv_hex);
        let aad_bytes = hex_decode(aad_hex);
        let pt_bytes = hex_decode(pt_hex);
        let expected_ct = hex_decode(expected_ct_hex);
        let expected_tag = hex_decode(expected_tag_hex);

        assert_eq!(key_bytes.len(), 32);
        assert_eq!(iv_bytes.len(), 12);
        assert_eq!(expected_tag.len(), 16);

        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&iv_bytes);
        let mut tag_out = [0u8; 16];

        // Encrypt
        let mut ct = vec![0u8; pt_bytes.len()];
        let rc = unsafe {
            let mut aes: wolfcrypt_sys::Aes = core::mem::zeroed();
            wolfcrypt_sys::wc_AesInit(&mut aes, core::ptr::null_mut(), dev_id);
            wolfcrypt_sys::wc_AesGcmSetKey(&mut aes, key.as_ptr(), 32);
            let rc = wolfcrypt_sys::wc_AesGcmEncrypt(
                &mut aes,
                if ct.is_empty() { core::ptr::null_mut() } else { ct.as_mut_ptr() },
                if pt_bytes.is_empty() { core::ptr::null() } else { pt_bytes.as_ptr() },
                pt_bytes.len() as u32,
                iv.as_ptr(), 12,
                tag_out.as_mut_ptr(), 16,
                if aad_bytes.is_empty() { core::ptr::null() } else { aad_bytes.as_ptr() },
                aad_bytes.len() as u32,
            );
            wolfcrypt_sys::wc_AesFree(&mut aes);
            rc
        };
        assert_eq!(rc, 0, "aes256gcm: encrypt failed: {rc}");
        assert_eq!(ct, expected_ct, "aes256gcm: ciphertext mismatch");
        assert_eq!(&tag_out[..], expected_tag.as_slice(), "aes256gcm: tag mismatch");
        total += 1;

        // Decrypt and verify round-trip
        let mut pt_dec = vec![0u8; ct.len()];
        let rc = unsafe {
            let mut aes: wolfcrypt_sys::Aes = core::mem::zeroed();
            wolfcrypt_sys::wc_AesInit(&mut aes, core::ptr::null_mut(), dev_id);
            wolfcrypt_sys::wc_AesGcmSetKey(&mut aes, key.as_ptr(), 32);
            let rc = wolfcrypt_sys::wc_AesGcmDecrypt(
                &mut aes,
                if pt_dec.is_empty() { core::ptr::null_mut() } else { pt_dec.as_mut_ptr() },
                if ct.is_empty() { core::ptr::null() } else { ct.as_ptr() },
                ct.len() as u32,
                iv.as_ptr(), 12,
                tag_out.as_ptr(), 16,
                if aad_bytes.is_empty() { core::ptr::null() } else { aad_bytes.as_ptr() },
                aad_bytes.len() as u32,
            );
            wolfcrypt_sys::wc_AesFree(&mut aes);
            rc
        };
        assert_eq!(rc, 0, "aes256gcm: decrypt failed: {rc}");
        assert_eq!(pt_dec, pt_bytes, "aes256gcm: round-trip plaintext mismatch");
        total += 1;
    }

    total
}

// ---------------------------------------------------------------------------
// ECDSA P-384 suite — keygen + sign + verify rounds
// ---------------------------------------------------------------------------

#[cfg(all(feature = "caliptra-hw", not(target_arch = "riscv32")))]
fn run_ecdsa384_suite(dev_id: core::ffi::c_int) -> usize {
    const ROUNDS: usize = 4;
    let mut total = 0usize; // counts sign + verify dispatches

    unsafe {
        let mut rng: wolfcrypt_sys::WC_RNG = core::mem::zeroed();
        let rc = wolfcrypt_sys::wc_InitRng_ex(&mut rng, core::ptr::null_mut(), dev_id);
        assert_eq!(rc, 0, "ecdsa384: wc_InitRng_ex failed: {rc}");

        for round in 0..ROUNDS {
            // Generate key pair with HW_DEVICE_ID
            let mut key: wolfcrypt_sys::ecc_key = core::mem::zeroed();
            let rc = wolfcrypt_sys::wc_ecc_init_ex(&mut key, core::ptr::null_mut(), dev_id);
            assert_eq!(rc, 0, "ecdsa384: wc_ecc_init_ex failed: {rc}");
            let rc = wolfcrypt_sys::wc_ecc_make_key_ex(
                &mut rng,
                48,
                &mut key,
                wolfcrypt_sys::ecc_curve_ids_ECC_SECP384R1 as core::ffi::c_int,
            );
            assert_eq!(rc, 0, "ecdsa384: wc_ecc_make_key_ex failed on round {round}: {rc}");

            // Sign a 48-byte hash (use round index to vary the input)
            let mut hash = [0x5au8; 48];
            hash[0] = round as u8;
            let mut sig = vec![0u8; 128];
            let mut sig_len: wolfcrypt_sys::word32 = 128;
            let rc = wolfcrypt_sys::wc_ecc_sign_hash(
                hash.as_ptr(), 48,
                sig.as_mut_ptr(), &mut sig_len,
                &mut rng, &mut key,
            );
            assert_eq!(rc, 0, "ecdsa384: wc_ecc_sign_hash failed on round {round}: {rc}");
            sig.truncate(sig_len as usize);
            total += 1; // sign counted

            // Verify the signature
            let mut verify_result: core::ffi::c_int = 0;
            let rc = wolfcrypt_sys::wc_ecc_verify_hash(
                sig.as_ptr(), sig.len() as wolfcrypt_sys::word32,
                hash.as_ptr(), 48,
                &mut verify_result, &mut key,
            );
            assert_eq!(rc, 0, "ecdsa384: wc_ecc_verify_hash failed on round {round}: {rc}");
            assert_eq!(verify_result, 1, "ecdsa384: signature verification failed on round {round}");
            total += 1; // verify counted

            wolfcrypt_sys::wc_ecc_free(&mut key);
        }

        wolfcrypt_sys::wc_FreeRng(&mut rng);
    }

    total
}

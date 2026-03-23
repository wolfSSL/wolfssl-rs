mod helpers;
use helpers::mac_equiv;

// Key lengths here equal the hash output length — a single convenient size
// that is valid for all HMAC variants.  This deliberately does NOT exercise
// HMAC's key-padding paths (keys shorter than the block size are zero-padded;
// keys longer than the block size are hashed first).  Those edge cases are
// covered by the Wycheproof HMAC vectors in wycheproof_mac.rs, which include
// varying key sizes.

mac_equiv!(
    hmac_sha1,
    wolfcrypt::WolfHmacSha1,
    hmac::Hmac<sha1::Sha1>,
    20,
    "HMAC",
    [wolfssl_openssl_extra, wolfssl_hmac]
);

mac_equiv!(
    hmac_sha256,
    wolfcrypt::WolfHmacSha256,
    hmac::Hmac<sha2::Sha256>,
    32,
    "HMAC",
    [wolfssl_openssl_extra, wolfssl_hmac]
);

mac_equiv!(
    hmac_sha384,
    wolfcrypt::WolfHmacSha384,
    hmac::Hmac<sha2::Sha384>,
    48,
    "HMAC",
    [wolfssl_openssl_extra, wolfssl_hmac, wolfssl_sha384]
);

mac_equiv!(
    hmac_sha512,
    wolfcrypt::WolfHmacSha512,
    hmac::Hmac<sha2::Sha512>,
    64,
    "HMAC",
    [wolfssl_openssl_extra, wolfssl_hmac, wolfssl_sha512]
);

mod helpers;
use helpers::mac_equiv;

mac_equiv!(
    cmac_aes128,
    wolfcrypt::WolfCmacAes128,
    cmac::Cmac<aes::Aes128>,
    16,
    "CMAC",
    [wolfssl_openssl_extra, wolfssl_cmac]
);

mac_equiv!(
    cmac_aes256,
    wolfcrypt::WolfCmacAes256,
    cmac::Cmac<aes::Aes256>,
    32,
    "CMAC",
    [wolfssl_openssl_extra, wolfssl_cmac]
);

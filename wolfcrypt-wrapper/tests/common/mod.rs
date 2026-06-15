#[cfg(fips)]
fn setup_fips() {
    use wolfcrypt_wrapper::fips;
    fips::set_private_key_read_enable(1).expect("Error with set_private_key_read_enable()");
}

#[expect(dead_code)]
pub fn setup() {
    #[cfg(fips)]
    setup_fips();
}

/// Return the path to a file under the wolfSSL source tree's `certs/` directory.
#[expect(dead_code)]
pub fn cert_path(relative: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("WOLFSSL_DIR"))
        .join("certs")
        .join(relative)
}

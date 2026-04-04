// Step 2 link probe: calls wolfcrypt_dpe_hw::init() and nothing else.
// Compiled with rustc --edition 2021 --crate-type bin (no -I headers).
extern crate wolfcrypt_dpe_hw;

fn main() {
    let _ = wolfcrypt_dpe_hw::init();
}

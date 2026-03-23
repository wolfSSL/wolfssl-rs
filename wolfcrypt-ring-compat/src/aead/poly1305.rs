// Copyright 2015-2016 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright wolfSSL Inc.
// SPDX-License-Identifier: MIT

// TODO: enforce maximum input length.

use super::{Tag, TAG_LEN};
use crate::wolfcrypt_rs::{wc_Poly1305SetKey, wc_Poly1305Update, wc_Poly1305Final};
use crate::cipher::block::BLOCK_LEN;
use core::mem::MaybeUninit;

/// A Poly1305 key.
pub(super) struct Key {
    pub(super) key_and_nonce: [u8; KEY_LEN],
}

const KEY_LEN: usize = 2 * BLOCK_LEN;

impl Key {
    #[inline]
    #[allow(dead_code)]
    pub(super) fn new(key_and_nonce: [u8; KEY_LEN]) -> Self {
        Self { key_and_nonce }
    }
}

pub struct Context {
    state: poly1305_state,
}

// Keep in sync with `poly1305_state` in GFp/poly1305.h.
//
// The C code, in particular the way the `poly1305_aligned_state` functions
// are used, is only correct when the state buffer is 64-byte aligned.
#[repr(C, align(64))]
#[allow(non_camel_case_types)]
struct poly1305_state(wolfcrypt_rs::poly1305_state);

impl Context {
    #[inline]
    pub(super) fn from_key(Key { key_and_nonce }: Key) -> Self {
        // SAFETY: MaybeUninit used for poly1305_state; fully initialized by wc_Poly1305SetKey.
        unsafe {
            let mut state = MaybeUninit::<poly1305_state>::uninit();
            wc_Poly1305SetKey(&mut (*state.as_mut_ptr()).0, key_and_nonce.as_ptr(), 32);
            Self {
                state: state.assume_init(),
            }
        }
    }

    #[inline]
    pub fn update(&mut self, input: &[u8]) {
        // SAFETY: state is valid (initialized in from_key); pointer/length from a valid Rust slice.
        unsafe {
            wc_Poly1305Update(
                &mut self.state.0,
                input.as_ptr(),
                input.len() as u32,
            );
        }
    }

    #[inline]
    pub(super) fn finish(mut self) -> Tag {
        // SAFETY: state is valid; tag is fully initialized by wc_Poly1305Final.
        unsafe {
            let mut tag = MaybeUninit::<[u8; TAG_LEN]>::uninit();
            wc_Poly1305Final(&mut self.state.0, tag.as_mut_ptr().cast());
            crate::fips::set_fips_service_status_unapproved();
            Tag(tag.assume_init(), TAG_LEN)
        }
    }
}

/// Implements the original, non-IETF padding semantics.
///
/// This is used by `chacha20_poly1305_openssh` and the standalone
/// poly1305 test vectors.
#[inline]
pub(super) fn sign(key: Key, input: &[u8]) -> Tag {
    let mut ctx = Context::from_key(key);
    ctx.update(input);
    ctx.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{test, test_file};

    // Adapted from BoringSSL's crypto/poly1305/poly1305_test.cc.
    #[test]
    pub fn test_poly1305() {
        test::run(
            test_file!("data/poly1305_test.txt"),
            |section, test_case| {
                assert_eq!(section, "");
                let key = test_case.consume_bytes("Key");
                let key: &[u8; BLOCK_LEN * 2] = key.as_slice().try_into().unwrap();
                let input = test_case.consume_bytes("Input");
                let expected_mac = test_case.consume_bytes("MAC");
                let key = Key::new(*key);
                let Tag(actual_mac, _) = sign(key, &input);
                assert_eq!(expected_mac, actual_mac.as_ref());

                Ok(())
            },
        );
    }
}

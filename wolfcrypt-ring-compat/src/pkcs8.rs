// Copyright 2017 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright wolfSSL Inc.
// SPDX-License-Identifier: MIT

//! PKCS#8 is specified in [RFC 5208].
//!
//! [RFC 5208]: https://tools.ietf.org/html/rfc5208.

use zeroize::Zeroize;

#[cfg(not(feature = "std"))]
use crate::prelude::*;

/// A generated PKCS#8 document.
pub struct Document {
    bytes: Vec<u8>,
}

impl Document {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

impl AsRef<[u8]> for Document {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for Document {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

#[derive(Copy, Clone)]
pub(crate) enum Version {
    V1,
    V2,
}

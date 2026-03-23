use zeroize::Zeroize;

#[cfg(not(feature = "std"))]
use crate::prelude::*;

pub(crate) struct LcCBB {
    buf: Vec<u8>,
}

impl LcCBB {
    pub(crate) fn new(initial_capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(initial_capacity.max(64)),
        }
    }

    pub(crate) fn into_vec(mut self) -> Result<Vec<u8>, crate::error::Unspecified> {
        // Take the vec out, replacing with empty vec (no allocation).
        // Drop will zeroize the empty vec (no-op).
        Ok(core::mem::take(&mut self.buf))
    }

    /// Write raw bytes
    #[allow(dead_code)]
    pub(crate) fn extend(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    #[allow(dead_code)]
    pub(crate) fn len(&self) -> usize {
        self.buf.len()
    }

    /// Get a mutable pointer for writing `n` bytes at current position.
    /// Advances length by `n`. Caller must write exactly `n` bytes.
    /// # Safety
    /// Caller must write exactly `n` bytes to the returned pointer.
    pub(crate) unsafe fn reserve_uninit(&mut self, n: usize) -> *mut u8 {
        self.buf.reserve(n);
        let pos = self.buf.len();
        self.buf.set_len(pos + n);
        self.buf.as_mut_ptr().add(pos)
    }

    /// Add an ASN.1 BOOLEAN value.
    #[allow(dead_code)]
    pub(crate) fn add_asn1_bool(&mut self, value: bool) {
        self.buf.push(0x01); // BOOLEAN tag
        self.buf.push(0x01); // length
        self.buf.push(if value { 0xFF } else { 0x00 });
    }
}

impl Drop for LcCBB {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::LcCBB;

    #[test]
    fn dynamic_vec() {
        let mut cbb = LcCBB::new(4);
        cbb.add_asn1_bool(true);
        let vec = cbb.into_vec().expect("be copied to buffer");
        assert_eq!(vec.as_slice(), &[1, 1, 255]);
    }

    #[test]
    fn dynamic_buffer_grows() {
        let mut cbb = LcCBB::new(1);
        cbb.add_asn1_bool(true);
        let vec = cbb.into_vec().expect("be copied to buffer");
        assert_eq!(vec.as_slice(), &[1, 1, 255]);
    }

    #[test]
    fn extend_bytes() {
        let mut cbb = LcCBB::new(8);
        cbb.extend(&[0x01, 0x02, 0x03]);
        cbb.extend(&[0x04, 0x05]);
        let vec = cbb.into_vec().expect("get vec");
        assert_eq!(vec.as_slice(), &[0x01, 0x02, 0x03, 0x04, 0x05]);
    }

    #[test]
    fn reserve_uninit() {
        let mut cbb = LcCBB::new(8);
        // SAFETY: writing exactly 3 bytes to the pointer returned by reserve_uninit(3).
        unsafe {
            let ptr = cbb.reserve_uninit(3);
            *ptr = 0xAA;
            *ptr.add(1) = 0xBB;
            *ptr.add(2) = 0xCC;
        }
        let vec = cbb.into_vec().expect("get vec");
        assert_eq!(vec.as_slice(), &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn add_asn1_bool_false() {
        let mut cbb = LcCBB::new(4);
        cbb.add_asn1_bool(false);
        let vec = cbb.into_vec().expect("get vec");
        assert_eq!(vec.as_slice(), &[1, 1, 0]);
    }
}

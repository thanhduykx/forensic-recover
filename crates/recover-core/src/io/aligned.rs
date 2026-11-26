use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;

/// Page-aligned (4 KiB) heap buffer required for `FILE_FLAG_NO_BUFFERING` (Windows)
/// and `O_DIRECT` (Linux) raw device I/O.
pub struct AlignedBuffer {
    ptr: NonNull<u8>,
    len: usize,
    layout: Layout,
}

unsafe impl Send for AlignedBuffer {}
unsafe impl Sync for AlignedBuffer {}

impl AlignedBuffer {
    pub const ALIGNMENT: usize = 4096;

    /// Allocates a zeroed buffer whose base address is aligned to 4096 bytes
    /// and whose capacity is rounded up to a multiple of 4096 bytes.
    pub fn new(min_len: usize) -> Self {
        let len = min_len.max(Self::ALIGNMENT);
        let aligned_len = (len + Self::ALIGNMENT - 1) & !(Self::ALIGNMENT - 1);
        let layout = Layout::from_size_align(aligned_len, Self::ALIGNMENT)
            .expect("valid 4KiB-aligned layout");
        // SAFETY: `aligned_len` is non-zero and multiple of 4096.
        let raw = unsafe { alloc_zeroed(layout) };
        let ptr = NonNull::new(raw).unwrap_or_else(|| std::alloc::handle_alloc_error(layout));
        Self {
            ptr,
            len: aligned_len,
            layout,
        }
    }

    pub fn capacity(&self) -> usize {
        self.len
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.ptr.as_ptr()
    }

    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: `ptr` is valid for `len` bytes and initialized by `alloc_zeroed`.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: `ptr` is uniquely owned and valid for `len` bytes.
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

impl Deref for AlignedBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl DerefMut for AlignedBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_slice()
    }
}

impl Drop for AlignedBuffer {
    fn drop(&mut self) {
        // SAFETY: `ptr` and `layout` match the `alloc_zeroed` call in `new`.
        unsafe {
            dealloc(self.ptr.as_ptr(), self.layout);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffer_is_4k_aligned() {
        let mut buf = AlignedBuffer::new(5000);
        assert_eq!(buf.as_ptr() as usize % 4096, 0);
        assert_eq!(buf.capacity(), 8192);
        buf[4096] = 0xAA;
        assert_eq!(buf[4096], 0xAA);
    }
}

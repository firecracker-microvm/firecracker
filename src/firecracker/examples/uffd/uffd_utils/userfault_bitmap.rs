// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};

/// `UserfaultBitmap` implements a simple bit map on the page level with test and set operations.
/// It is page-size aware, so it converts addresses to page numbers before setting or clearing
/// the bits.
#[derive(Debug)]
pub struct UserfaultBitmap {
    map: *mut AtomicU64,
    size: usize,
    byte_size: usize,
    page_size: NonZeroUsize,
    map_size: usize,
}

impl UserfaultBitmap {
    /// Create a new bitmap using a user-supplied pointer.
    ///
    /// # Safety
    ///
    /// Caller must ensure:
    /// * `map_ptr` points to a valid region of memory containing initialized `AtomicU64` elements
    /// * `map_ptr` is properly aligned for `AtomicU64`
    /// * The memory region contains enough space for `ceil(ceil(byte_size/page_size)/64)` elements
    /// * The memory region pointed to by `map_ptr` must not be accessed through any other means
    ///   while this `UserfaultBitmap` exists
    /// * The caller must ensure the memory remains valid for the lifetime of the returned
    ///   `UserfaultBitmap`
    pub unsafe fn new(map_ptr: *mut AtomicU64, byte_size: usize, page_size: NonZeroUsize) -> Self {
        let num_pages = byte_size.div_ceil(page_size.get());
        let map_size = num_pages.div_ceil(u64::BITS as usize);

        UserfaultBitmap {
            map: map_ptr,
            size: num_pages,
            byte_size,
            page_size,
            map_size,
        }
    }

    /// Is bit `n` set? Bits outside the range of the bitmap are always unset.
    pub fn is_bit_set(&self, index: usize) -> bool {
        if index < self.size {
            unsafe {
                let map_entry = &*self.map.add(index >> 6);
                (map_entry.load(Ordering::Acquire) & (1 << (index & 63))) != 0
            }
        } else {
            // Out-of-range bits are always unset.
            false
        }
    }

    /// Reset a range of `len` bytes starting at `start_addr`. The first bit set in the bitmap
    /// is for the page corresponding to `start_addr`, and the last bit that we set corresponds
    /// to address `start_addr + len - 1`.
    pub fn reset_addr_range(&self, start_addr: usize, len: usize) {
        if len == 0 {
            return;
        }

        let first_bit = start_addr / self.page_size;
        let last_bit = start_addr.saturating_add(len - 1) / self.page_size;

        for n in first_bit..=last_bit {
            if n >= self.size {
                break;
            }
            unsafe {
                let map_entry = &*self.map.add(n >> 6);
                map_entry.fetch_and(!(1 << (n & 63)), Ordering::SeqCst);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU64;

    use super::*;

    // Helper function to create a test bitmap
    fn setup_test_bitmap(
        byte_size: usize,
        page_size: NonZeroUsize,
    ) -> (Vec<AtomicU64>, UserfaultBitmap) {
        let num_pages = byte_size.div_ceil(page_size.get());
        let map_size = num_pages.div_ceil(u64::BITS as usize);
        let mut memory = Vec::with_capacity(map_size);
        for _ in 0..map_size {
            memory.push(AtomicU64::new(0));
        }
        let ptr = memory.as_mut_ptr();
        let bitmap = unsafe { UserfaultBitmap::new(ptr, byte_size, page_size) };
        (memory, bitmap)
    }

    #[test]
    fn test_basic_initialization() {
        let page_size = NonZeroUsize::new(128).unwrap();
        let (_memory, bitmap) = setup_test_bitmap(1024, page_size);

        assert!(!bitmap.is_bit_set(0));
        assert!(!bitmap.is_bit_set(7));
    }

    #[test]
    fn test_out_of_bounds_access() {
        let page_size = NonZeroUsize::new(128).unwrap();
        let (_memory, bitmap) = setup_test_bitmap(1024, page_size);

        // With 1024 bytes and 128-byte pages, we should have 8 pages
        assert!(!bitmap.is_bit_set(8)); // This should be out of bounds
        assert!(!bitmap.is_bit_set(100)); // This should be out of bounds
    }

    #[test]
    fn test_reset_addr_range() {
        let page_size = NonZeroUsize::new(128).unwrap();
        let (memory, bitmap) = setup_test_bitmap(1024, page_size);

        // Set bits 0 and 1 (representing first two pages)
        memory[0].store(0b11, Ordering::SeqCst);

        // Verify bits are set
        assert!(bitmap.is_bit_set(0));
        assert!(bitmap.is_bit_set(1));
        assert!(!bitmap.is_bit_set(2));

        // Reset first page
        bitmap.reset_addr_range(0, 128);

        // Verify first bit is reset but second remains set
        assert!(!bitmap.is_bit_set(0));
        assert!(bitmap.is_bit_set(1));
    }

    #[test]
    fn test_reset_addr_range_spanning_multiple_words() {
        let page_size = NonZeroUsize::new(128).unwrap();
        // Ensure we allocate enough space for at least 2 words (128 bits)
        let (memory, bitmap) = setup_test_bitmap(128 * 128, page_size); // 128 pages

        // Set bits in different words
        memory[0].store(u64::MAX, Ordering::SeqCst);
        memory[1].store(u64::MAX, Ordering::SeqCst);

        // Reset a range spanning both words
        bitmap.reset_addr_range(63 * 128, 256); // Reset bits 63 and 64

        // Check bits are reset
        assert!(!bitmap.is_bit_set(63));
        assert!(!bitmap.is_bit_set(64));
        // Check adjacent bits are still set
        assert!(bitmap.is_bit_set(62));
        assert!(bitmap.is_bit_set(65));
    }

    #[test]
    fn test_reset_addr_range_zero_length() {
        let page_size = NonZeroUsize::new(128).unwrap();
        let (memory, bitmap) = setup_test_bitmap(1024, page_size);

        // Set a bit manually
        memory[0].store(1, Ordering::SeqCst);

        // Reset with length 0
        bitmap.reset_addr_range(0, 0);

        // Bit should still be set
        assert!(bitmap.is_bit_set(0));
    }

    #[test]
    fn test_reset_addr_range_beyond_bounds() {
        let page_size = NonZeroUsize::new(128).unwrap();
        let (_memory, bitmap) = setup_test_bitmap(1024, page_size);

        // This should not panic
        bitmap.reset_addr_range(1024, 2048);
    }

    #[test]
    fn test_edge_cases() {
        // Test with minimum page size
        let page_size = NonZeroUsize::new(1).unwrap();
        let (_memory, bitmap) = setup_test_bitmap(64, page_size);
        assert!(!bitmap.is_bit_set(0));

        // Test with zero byte_size
        let page_size = NonZeroUsize::new(128).unwrap();
        let (_memory, bitmap) = setup_test_bitmap(0, page_size);
        assert!(!bitmap.is_bit_set(0));

        // Test reset_addr_range with maximum usize value
        bitmap.reset_addr_range(usize::MAX - 128, 256);
    }
}

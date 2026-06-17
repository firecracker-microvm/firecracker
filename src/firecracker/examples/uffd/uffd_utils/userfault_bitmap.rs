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

        let first_bit = start_addr / self.page_size.get();
        if first_bit >= self.size {
            return;
        }

        let last_bit =
            (start_addr.saturating_add(len - 1) / self.page_size.get()).min(self.size - 1);
        let first_word = first_bit >> 6;
        let last_word = last_bit >> 6;

        for word in first_word..=last_word {
            let start = if word == first_word {
                first_bit & 63
            } else {
                0
            };
            let end = if word == last_word { last_bit & 63 } else { 63 };
            let width = end - start + 1;
            let mask = if width == u64::BITS as usize {
                u64::MAX
            } else {
                ((1u64 << width) - 1) << start
            };

            unsafe {
                let map_entry = &*self.map.add(word);
                // Clearing a bit tells KVM to stop intercepting faults for this page. KVM reads
                // the bitmap with a plain copy_from_user() (no acquire), so ordering is NOT
                // established by an acquire/release pair on the bitmap itself. It is established
                // by the full barriers that always bracket this clear:
                //   * the page contents are published by the preceding populate syscall
                //     (pwrite64 to guest_memfd / UFFDIO_COPY ioctl), and
                //   * the clear becomes visible to KVM only after a later release store on the
                //     completion-ring head (exitless APF) or a socket round-trip (sync fault),
                //     each of which orders this store ahead of the kernel's re-read.
                // Release keeps populate-before-clear self-contained without SeqCst's full
                // barrier (which is pointless on weaker ISAs and identical on x86, where this
                // locked RMW is already a full barrier). The real win is clearing a whole word
                // of pages per RMW instead of one RMW per page.
                map_entry.fetch_and(!mask, Ordering::Release);
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
    fn test_reset_addr_range_full_word_width() {
        // page_size = 1 byte so that bit N maps to byte N, making it easy to clear
        // exactly 64 contiguous bits (a whole word). This exercises the `width == 64`
        // branch in `reset_addr_range`, which must use `u64::MAX` to avoid the
        // `1u64 << 64` shift overflow.
        let page_size = NonZeroUsize::new(1).unwrap();
        let (memory, bitmap) = setup_test_bitmap(128, page_size); // 128 pages, 2 words
        memory[0].store(u64::MAX, Ordering::SeqCst);
        memory[1].store(u64::MAX, Ordering::SeqCst);

        // Clear exactly word 0 (bits 0..=63); word 1 must be untouched.
        bitmap.reset_addr_range(0, 64);
        assert_eq!(memory[0].load(Ordering::SeqCst), 0);
        assert_eq!(memory[1].load(Ordering::SeqCst), u64::MAX);

        // Clear the remaining full word (bits 64..=127), spanning a whole second word.
        bitmap.reset_addr_range(64, 64);
        assert_eq!(memory[1].load(Ordering::SeqCst), 0);
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

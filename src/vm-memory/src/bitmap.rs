// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
//! Atomic bitmap implementation.

// Temporarly disable unused warnings.
// TODO: remove these once the Bitmap integration is completed.
#![allow(dead_code)]

use std::sync::atomic::{AtomicU64, Ordering};

/// `Bitmap` implements a simple bit map on the page level with test and set operations. It is
/// page-size aware, so it converts addresses to page numbers before setting or clearing the bits.
#[derive(Debug)]
pub struct Bitmap {
    map: Vec<AtomicU64>,
    size: usize,
    page_size: usize,
}

impl Bitmap {
    /// Create a new bitmap of `byte_size`, with one bit per `page_size`.
    /// In reality this is rounded up, and you get a new vector of the next multiple of 64 bigger
    /// than `size` for free.
    pub fn new(byte_size: usize, page_size: usize) -> Self {
        // Bit size is the number of bits in the bitmap, always at least 1 (to store the state of
        // the '0' address).
        let bit_size = std::cmp::max(1, byte_size / page_size);
        // Create the map of `AtomicU64`, allowing the bit set operations to be done on a non-mut
        // `Bitmap`, avoiding the need for a Mutex or other serialization.
        let map_size = ((bit_size - 1) >> 6) + 1;
        let map: Vec<AtomicU64> = (0..map_size).map(|_| AtomicU64::new(0)).collect();

        Bitmap {
            map,
            size: bit_size,
            page_size,
        }
    }

    /// Is bit `n` set? Bits outside the range of the bitmap are always unset.
    #[inline]
    pub fn is_bit_set(&self, n: usize) -> bool {
        if n <= self.size {
            (self.map[n >> 6].load(Ordering::SeqCst) & (1 << (n & 63))) != 0
        } else {
            // Out-of-range bits are always unset.
            false
        }
    }

    /// Is the bit corresponding to address `addr` set?
    pub fn is_addr_set(&self, addr: usize) -> bool {
        self.is_bit_set(addr / self.page_size)
    }

    /// Set a range of bits starting at `start_addr` and continuing for the next `len` bytes.
    pub fn set_addr_range(&self, start_addr: usize, len: usize) {
        let first_bit = start_addr / self.page_size;
        let page_count = (len + self.page_size - 1) / self.page_size;
        for n in first_bit..(first_bit + page_count) {
            if n > self.size {
                // Attempts to set bits beyond the end of the bitmap are simply ignored.
                break;
            }
            self.map[n >> 6].fetch_or(1 << (n & 63), Ordering::SeqCst);
        }
    }

    /// Get the length of the bitmap in bits (i.e. in how many pages it can represent).
    pub fn len(&self) -> usize {
        self.size
    }

    /// Is the bitmap empty (i.e. has zero size)? This is always false, because we explicitly
    /// round up the size when creating the bitmap. We will not need this function but:
    /// https://rust-lang.github.io/rust-clippy/master/index.html#len_without_is_empty
    pub fn is_empty(&self) -> bool {
        false
    }
}

/// Implementing `Clone` for `Bitmap` allows us to return a deep copy of the bitmap for taking
/// snapshots and other metrics. This copy is sequentially consistent (in that it reflects all
/// changes that happen-before the clone), but not consistent in the face of concurrent writes
/// (i.e. any writes that happen concurrently with .clone() may or may not be reflected).
impl Clone for Bitmap {
    fn clone(&self) -> Self {
        let map = self
            .map
            .iter()
            .map(|i| i.load(Ordering::SeqCst))
            .map(AtomicU64::new)
            .collect();
        Bitmap {
            map,
            size: self.size,
            page_size: self.page_size,
        }
    }
}

mod tests {
    #[test]
    fn bitmap_basic() {
        use super::Bitmap;
        let b = Bitmap::new(1024, 128);
        assert_eq!(b.is_empty(), false);
        assert_eq!(b.len(), 8);
        b.set_addr_range(128, 129);
        assert!(!b.is_addr_set(0));
        assert!(b.is_addr_set(128));
        assert!(b.is_addr_set(256));
        assert!(!b.is_addr_set(384));

        #[allow(clippy::redundant_clone)]
        let copy_b = b.clone();
        assert!(copy_b.is_addr_set(256));
        assert!(!copy_b.is_addr_set(384));
    }

    #[test]
    fn bitmap_out_of_range() {
        use super::Bitmap;
        let b = Bitmap::new(1024, 128);
        // Set a partial range that goes beyond the end of the bitmap
        b.set_addr_range(768, 512);
        assert!(b.is_addr_set(768));
        // The bitmap is never set beyond its end
        assert!(!b.is_addr_set(1152));
    }
}

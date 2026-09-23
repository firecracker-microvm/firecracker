// Copyright 2026 Superserve AI. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Dirty bitmap for tracking modified blocks in an overlay filesystem.
//!
//! Tracks which blocks have been written to, enabling efficient delta snapshots
//! that only persist modified blocks.

use bitvec::vec::BitVec;

/// Default block size for dirty tracking (4KB — matches host page size).
pub const DEFAULT_BLOCK_SIZE: u32 = 4096;

/// Minimum allowed block size (must be at least one sector).
const MIN_BLOCK_SIZE: u32 = 512;

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum DirtyBitmapError {
    /// Invalid block size: {0} (must be power of 2, >= 512)
    InvalidBlockSize(u32),
    /// Bitmap data length mismatch: expected {expected}, got {actual}
    LengthMismatch { expected: usize, actual: usize },
    /// Disk size is zero
    ZeroDiskSize,
    /// Block index {index} out of bounds (total_blocks={total_blocks})
    OutOfBounds { index: u64, total_blocks: u64 },
    /// Disk size overflow: disk_size_bytes={disk_size_bytes}, block_size={block_size}
    DiskSizeOverflow { disk_size_bytes: u64, block_size: u32 },
    /// Scanning the overlay's extents failed: {0}
    Scan(std::io::Error),
    /// Overlay filesystem allocation unit {blksize} exceeds the block size {block_size}; extents cannot be trusted at block granularity
    AllocationUnit { blksize: u64, block_size: u32 },
}

#[derive(Debug, Clone)]
pub struct DirtyBitmap {
    bits: BitVec,
    block_size: u32,
    total_blocks: u64,
}

impl DirtyBitmap {
    /// Create a new dirty bitmap for a disk of `disk_size_bytes` with the given block granularity.
    pub fn new(disk_size_bytes: u64, block_size: u32) -> Result<Self, DirtyBitmapError> {
        if disk_size_bytes == 0 {
            return Err(DirtyBitmapError::ZeroDiskSize);
        }
        if block_size < MIN_BLOCK_SIZE || !block_size.is_power_of_two() {
            return Err(DirtyBitmapError::InvalidBlockSize(block_size));
        }

        let block_size_u64 = u64::from(block_size);
        // Ceiling division: number of blocks needed to cover the entire disk.
        let total_blocks = disk_size_bytes
            .checked_add(block_size_u64 - 1)
            .ok_or(DirtyBitmapError::DiskSizeOverflow {
                disk_size_bytes,
                block_size,
            })?
            / block_size_u64;

        Ok(Self {
            bits: BitVec::repeat(false, total_blocks as usize),
            block_size,
            total_blocks,
        })
    }

    /// Derive the bitmap from the overlay file itself: every allocated extent
    /// is a block the guest wrote, every hole falls through to the base. That
    /// holds for an overlay this engine wrote and for one restored from a
    /// backup of it, and it is refused on a filesystem whose allocation unit
    /// is coarser than a block, where a hole beside data would read as data.
    pub fn from_overlay_extents(
        overlay: &std::fs::File,
        disk_size_bytes: u64,
        block_size: u32,
    ) -> Result<Self, DirtyBitmapError> {
        use std::os::unix::fs::MetadataExt;
        let mut bitmap = Self::new(disk_size_bytes, block_size)?;
        let blksize = overlay.metadata().map_err(DirtyBitmapError::Scan)?.blksize();
        if blksize > u64::from(block_size) {
            return Err(DirtyBitmapError::AllocationUnit {
                blksize,
                block_size,
            });
        }
        crate::utils::sparse::for_each_data_extent(overlay, disk_size_bytes, |start, end| {
            let mut at = start;
            while at < end {
                let len = (end - at).min(u64::from(u32::MAX));
                bitmap.set(at, len as u32);
                at += len;
            }
        })
        .map_err(DirtyBitmapError::Scan)?;
        Ok(bitmap)
    }

    /// Mark all blocks covering the byte range `[offset, offset + len)` as dirty.
    pub fn set(&mut self, offset: u64, len: u32) {
        if len == 0 {
            return;
        }
        let start_block = self.offset_to_block(offset);
        let end_offset = offset.saturating_add(u64::from(len)).saturating_sub(1);
        let end_block = self.offset_to_block(end_offset);

        let clamped_end = end_block.min(self.total_blocks - 1);
        for block in start_block..=clamped_end {
            self.bits.set(block as usize, true);
        }
    }

    /// Mark a specific block as clean.
    pub fn unset(&mut self, block_idx: u64) {
        if block_idx < self.total_blocks {
            self.bits.set(block_idx as usize, false);
        }
    }

    /// Check whether a specific block index is dirty.
    pub fn is_set(&self, block_idx: u64) -> bool {
        if block_idx >= self.total_blocks {
            return false;
        }
        self.bits[block_idx as usize]
    }

    /// Check whether all blocks in a byte range have the same dirty state.
    ///
    /// Returns:
    /// - `Some(true)` if all blocks in the range are dirty
    /// - `Some(false)` if all blocks in the range are clean
    /// - `None` if the range is mixed, or starts past the disk end
    pub fn is_range_uniform(&self, offset: u64, len: u32) -> Option<bool> {
        if len == 0 {
            return Some(false);
        }
        let start_block = self.offset_to_block(offset);
        if start_block >= self.total_blocks {
            return None;
        }
        let end_offset = offset.saturating_add(u64::from(len)).saturating_sub(1);
        let end_block = self.offset_to_block(end_offset).min(self.total_blocks - 1);

        let first = self.is_set(start_block);
        for block in (start_block + 1)..=end_block {
            if self.is_set(block) != first {
                return None;
            }
        }
        Some(first)
    }

    /// Clear all dirty bits.
    pub fn clear(&mut self) {
        self.bits.fill(false);
    }

    /// Return the number of dirty blocks.
    pub fn dirty_count(&self) -> u64 {
        self.bits.count_ones() as u64
    }

    /// Iterate over the indices of all dirty blocks.
    pub fn iter_dirty(&self) -> impl Iterator<Item = u64> + '_ {
        self.bits
            .iter()
            .enumerate()
            .filter(|(_, bit)| **bit)
            .map(|(idx, _)| idx as u64)
    }

    /// Serialize the bitmap to bytes for snapshot persistence.
    pub fn serialize(&self) -> Vec<u8> {
        let raw_slice = self.bits.as_raw_slice();
        let mut bytes = Vec::with_capacity(raw_slice.len() * std::mem::size_of::<usize>());
        for &word in raw_slice {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        bytes
    }

    /// Deserialize a bitmap from bytes, validating the data.
    pub fn deserialize(
        bytes: &[u8],
        block_size: u32,
        total_blocks: u64,
    ) -> Result<Self, DirtyBitmapError> {
        if total_blocks == 0 {
            return Err(DirtyBitmapError::ZeroDiskSize);
        }
        if block_size < MIN_BLOCK_SIZE || !block_size.is_power_of_two() {
            return Err(DirtyBitmapError::InvalidBlockSize(block_size));
        }

        let bits_needed = total_blocks as usize;
        let words_needed = (bits_needed + (usize::BITS as usize - 1)) / usize::BITS as usize;
        let expected_len = words_needed * std::mem::size_of::<usize>();

        if bytes.len() != expected_len {
            return Err(DirtyBitmapError::LengthMismatch {
                expected: expected_len,
                actual: bytes.len(),
            });
        }

        let word_size = std::mem::size_of::<usize>();
        let mut raw: Vec<usize> = Vec::with_capacity(words_needed);
        for chunk in bytes.chunks_exact(word_size) {
            let mut word_bytes = [0u8; std::mem::size_of::<usize>()];
            word_bytes.copy_from_slice(chunk);
            raw.push(usize::from_le_bytes(word_bytes));
        }

        let mut bits = BitVec::from_vec(raw);
        bits.truncate(bits_needed);

        Ok(Self {
            bits,
            block_size,
            total_blocks,
        })
    }

    /// Get the block size in bytes.
    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    /// Get the total number of blocks.
    pub fn total_blocks(&self) -> u64 {
        self.total_blocks
    }

    /// Convert a byte offset to a block index.
    fn offset_to_block(&self, offset: u64) -> u64 {
        offset / u64::from(self.block_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DISK_SIZE: u64 = 1024 * 1024; // 1MB
    const BLOCK_SIZE: u32 = 4096;

    #[test]
    fn test_new_valid() {
        let bm = DirtyBitmap::new(DISK_SIZE, BLOCK_SIZE).unwrap();
        assert_eq!(bm.total_blocks(), 256); // 1MB / 4KB
        assert_eq!(bm.block_size(), BLOCK_SIZE);
        assert_eq!(bm.dirty_count(), 0);
    }

    #[test]
    fn test_new_non_aligned_disk_size() {
        // Disk size not a multiple of block size — should round up.
        let bm = DirtyBitmap::new(4097, 4096).unwrap();
        assert_eq!(bm.total_blocks(), 2);
    }

    #[test]
    fn test_new_zero_disk_size() {
        assert!(matches!(
            DirtyBitmap::new(0, BLOCK_SIZE),
            Err(DirtyBitmapError::ZeroDiskSize)
        ));
    }

    #[test]
    fn test_new_invalid_block_size() {
        // Not power of 2.
        assert!(matches!(
            DirtyBitmap::new(DISK_SIZE, 1000),
            Err(DirtyBitmapError::InvalidBlockSize(1000))
        ));
        // Too small.
        assert!(matches!(
            DirtyBitmap::new(DISK_SIZE, 256),
            Err(DirtyBitmapError::InvalidBlockSize(256))
        ));
    }

    #[test]
    fn test_set_and_is_set() {
        let mut bm = DirtyBitmap::new(DISK_SIZE, BLOCK_SIZE).unwrap();

        // Write at offset 0, length 512 — should dirty block 0.
        bm.set(0, 512);
        assert!(bm.is_set(0));
        assert!(!bm.is_set(1));
        assert_eq!(bm.dirty_count(), 1);

        // Write spanning two blocks (offset 4000, length 200) — blocks 0 and 1.
        bm.set(4000, 200);
        assert!(bm.is_set(0));
        assert!(bm.is_set(1));
        assert_eq!(bm.dirty_count(), 2);
    }

    #[test]
    fn test_set_last_block() {
        let mut bm = DirtyBitmap::new(DISK_SIZE, BLOCK_SIZE).unwrap();
        let last_offset = DISK_SIZE - 512;
        bm.set(last_offset, 512);
        assert!(bm.is_set(bm.total_blocks() - 1));
        assert_eq!(bm.dirty_count(), 1);
    }

    #[test]
    fn test_set_zero_len() {
        let mut bm = DirtyBitmap::new(DISK_SIZE, BLOCK_SIZE).unwrap();
        bm.set(0, 0);
        assert_eq!(bm.dirty_count(), 0);
    }

    #[test]
    fn test_is_set_out_of_bounds() {
        let bm = DirtyBitmap::new(DISK_SIZE, BLOCK_SIZE).unwrap();
        assert!(!bm.is_set(bm.total_blocks()));
        assert!(!bm.is_set(u64::MAX));
    }

    #[test]
    fn test_is_range_uniform() {
        let mut bm = DirtyBitmap::new(DISK_SIZE, BLOCK_SIZE).unwrap();

        // All clean.
        assert_eq!(bm.is_range_uniform(0, 8192), Some(false));

        // Dirty blocks 0 and 1.
        bm.set(0, 8192);
        assert_eq!(bm.is_range_uniform(0, 8192), Some(true));

        // Mixed: blocks 0-1 dirty, block 2 clean.
        assert_eq!(bm.is_range_uniform(0, 12288), None);

        // Zero length.
        assert_eq!(bm.is_range_uniform(0, 0), Some(false));
    }

    #[test]
    fn test_clear() {
        let mut bm = DirtyBitmap::new(DISK_SIZE, BLOCK_SIZE).unwrap();
        bm.set(0, 4096);
        bm.set(8192, 4096);
        assert_eq!(bm.dirty_count(), 2);

        bm.clear();
        assert_eq!(bm.dirty_count(), 0);
        assert!(!bm.is_set(0));
        assert!(!bm.is_set(2));
    }

    #[test]
    fn test_iter_dirty() {
        let mut bm = DirtyBitmap::new(DISK_SIZE, BLOCK_SIZE).unwrap();
        bm.set(0, 4096); // block 0
        bm.set(8192, 4096); // block 2
        bm.set(16384, 4096); // block 4

        let dirty: Vec<u64> = bm.iter_dirty().collect();
        assert_eq!(dirty, vec![0, 2, 4]);
    }

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        let mut bm = DirtyBitmap::new(DISK_SIZE, BLOCK_SIZE).unwrap();
        bm.set(0, 4096);
        bm.set(8192, 4096);
        bm.set(DISK_SIZE - 4096, 4096);

        let serialized = bm.serialize();
        let restored =
            DirtyBitmap::deserialize(&serialized, BLOCK_SIZE, bm.total_blocks()).unwrap();

        assert_eq!(restored.total_blocks(), bm.total_blocks());
        assert_eq!(restored.block_size(), bm.block_size());
        assert_eq!(restored.dirty_count(), bm.dirty_count());

        let orig_dirty: Vec<u64> = bm.iter_dirty().collect();
        let restored_dirty: Vec<u64> = restored.iter_dirty().collect();
        assert_eq!(orig_dirty, restored_dirty);
    }

    #[test]
    fn test_deserialize_invalid_length() {
        assert!(matches!(
            DirtyBitmap::deserialize(&[0u8; 3], BLOCK_SIZE, 256),
            Err(DirtyBitmapError::LengthMismatch { .. })
        ));
    }

    #[test]
    fn test_deserialize_invalid_block_size() {
        assert!(matches!(
            DirtyBitmap::deserialize(&[], 100, 10),
            Err(DirtyBitmapError::InvalidBlockSize(100))
        ));
    }

    #[test]
    fn test_deserialize_zero_total_blocks() {
        assert!(matches!(
            DirtyBitmap::deserialize(&[], BLOCK_SIZE, 0),
            Err(DirtyBitmapError::ZeroDiskSize)
        ));
    }

    #[test]
    fn test_sector_sized_block() {
        let mut bm = DirtyBitmap::new(4096, 512).unwrap();
        assert_eq!(bm.total_blocks(), 8);

        bm.set(512, 512); // block 1
        assert!(!bm.is_set(0));
        assert!(bm.is_set(1));
        assert!(!bm.is_set(2));
    }

    #[test]
    fn test_large_disk() {
        // 10GB disk with 4KB blocks = 2,621,440 blocks.
        let bm = DirtyBitmap::new(10 * 1024 * 1024 * 1024, BLOCK_SIZE).unwrap();
        assert_eq!(bm.total_blocks(), 2_621_440);
        assert_eq!(bm.dirty_count(), 0);
    }

    #[test]
    fn test_serialize_empty_bitmap() {
        let bm = DirtyBitmap::new(DISK_SIZE, BLOCK_SIZE).unwrap();
        let serialized = bm.serialize();
        let restored =
            DirtyBitmap::deserialize(&serialized, BLOCK_SIZE, bm.total_blocks()).unwrap();
        assert_eq!(restored.dirty_count(), 0);
    }

    #[test]
    fn test_serialize_full_bitmap() {
        let mut bm = DirtyBitmap::new(DISK_SIZE, BLOCK_SIZE).unwrap();
        bm.set(0, DISK_SIZE as u32);
        assert_eq!(bm.dirty_count(), bm.total_blocks());

        let serialized = bm.serialize();
        let restored =
            DirtyBitmap::deserialize(&serialized, BLOCK_SIZE, bm.total_blocks()).unwrap();
        assert_eq!(restored.dirty_count(), bm.total_blocks());
    }
}

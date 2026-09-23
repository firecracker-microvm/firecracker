// Copyright 2026 Superserve AI. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Synchronous copy-on-write overlay file engine.
//!
//! Routes reads between a shared read-only base image and a per-VM sparse overlay
//! file using a dirty bitmap. Writes always go to the overlay.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

use vm_memory::{GuestMemoryError, ReadVolatile, WriteVolatile};

use super::delta;
use super::dirty_bitmap::{DirtyBitmap, DirtyBitmapError};
use crate::logger::warn;
use crate::vstate::memory::{GuestAddress, GuestMemory, GuestMemoryMmap};

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum OverlayIoError {
    /// Base read seek: {0}
    BaseSeek(std::io::Error),
    /// Base read transfer: {0}
    BaseTransfer(GuestMemoryError),
    /// Base host read (copy-up): {0}
    BaseHostRead(std::io::Error),
    /// Overlay seek: {0}
    OverlaySeek(std::io::Error),
    /// Overlay read transfer: {0}
    OverlayReadTransfer(GuestMemoryError),
    /// Overlay write transfer: {0}
    OverlayWriteTransfer(GuestMemoryError),
    /// Overlay host write (copy-up): {0}
    OverlayHostWrite(std::io::Error),
    /// Overlay flush: {0}
    OverlayFlush(std::io::Error),
    /// Overlay sync: {0}
    OverlaySync(std::io::Error),
    /// Size mismatch: base={base_size}, overlay={overlay_size}
    SizeMismatch { base_size: u64, overlay_size: u64 },
    /// Overlay engine cannot be created via from_file — use DiskProperties::new_overlay()
    NotConstructibleFromFile,
    /// Bitmap error: {0}
    Bitmap(DirtyBitmapError),
    /// Flatten: open base read-write: {0}
    FlattenBaseOpen(std::io::Error),
    /// Flatten: read dirty block from overlay: {0}
    FlattenOverlayRead(std::io::Error),
    /// Flatten: write dirty block to base: {0}
    FlattenBaseWrite(std::io::Error),
    /// Flatten: sync base after writes: {0}
    FlattenBaseSync(std::io::Error),
    /// Flatten: base size mismatch: expected {expected}, actual {actual}
    FlattenBaseSizeMismatch { expected: u64, actual: u64 },
}

#[derive(Debug)]
pub struct OverlayFileEngine {
    base: File,
    overlay: File,
    bitmap: DirtyBitmap,
}

// OverlayFileEngine contains File and DirtyBitmap (Vec-backed), both of which are Send.
// No manual unsafe impl needed — derived automatically.

impl OverlayFileEngine {
    /// Create a new overlay engine from a read-only base file and a writable overlay file.
    ///
    /// The overlay file must have the same logical size as the base file (sparse is fine).
    /// If `bitmap` is `None`, it is derived from the overlay file's allocated
    /// extents, so an overlay that already holds guest-written blocks, such as
    /// one restored from a backup, is read rather than shadowed by the base.
    pub fn from_files(
        base: File,
        overlay: File,
        disk_size: u64,
        block_size: u32,
        bitmap: Option<DirtyBitmap>,
    ) -> Result<Self, OverlayIoError> {
        let bitmap = match bitmap {
            Some(bm) => bm,
            None => DirtyBitmap::from_overlay_extents(&overlay, disk_size, block_size)
                .map_err(OverlayIoError::Bitmap)?,
        };

        Ok(Self {
            base,
            overlay,
            bitmap,
        })
    }

    /// Update the overlay file handle.
    /// Note: this does NOT reset the bitmap. Callers must ensure the new overlay
    /// is consistent with the current bitmap state. Hot-update of overlay devices
    /// is rejected at the VirtioBlock level to prevent data corruption.
    pub(crate) fn update_overlay(&mut self, overlay: File) {
        self.overlay = overlay;
    }

    /// Get a reference to the dirty bitmap.
    pub fn bitmap(&self) -> &DirtyBitmap {
        &self.bitmap
    }

    /// Test fixture: write `content` to the overlay at `block_idx` and mark
    /// the block dirty. Gated by `test-fixtures`.
    #[cfg(feature = "test-fixtures")]
    pub fn force_dirty_block(
        &mut self,
        block_idx: u64,
        content: &[u8],
    ) -> Result<(), OverlayIoError> {
        use std::os::unix::fs::FileExt;
        let block_size = self.bitmap.block_size();
        assert_eq!(
            content.len(),
            block_size as usize,
            "force_dirty_block: content length must equal block_size"
        );
        let offset = block_idx * u64::from(block_size);
        self.overlay
            .write_all_at(content, offset)
            .map_err(OverlayIoError::OverlayHostWrite)?;
        self.bitmap.set(offset, block_size);
        Ok(())
    }

    /// Get a reference to the overlay file.
    #[cfg(test)]
    pub fn overlay_file(&self) -> &File {
        &self.overlay
    }

    /// Get a mutable reference to the overlay file (for delta export).
    pub fn overlay_file_mut(&mut self) -> &mut File {
        &mut self.overlay
    }

    /// Discard blocks in the overlay: clear bitmap bits and punch holes in the overlay file.
    pub fn discard(&mut self, offset: u64, len: u64) -> Result<(), OverlayIoError> {
        if len == 0 {
            return Ok(());
        }

        // Clear bitmap bits for the discarded range.
        let block_size = u64::from(self.bitmap.block_size());
        let start_block = offset / block_size;
        let end_offset = offset.saturating_add(len).saturating_sub(1);
        let end_block = end_offset / block_size;
        let clamped_end = end_block.min(self.bitmap.total_blocks() - 1);

        for block in start_block..=clamped_end {
            self.bitmap.unset(block);
        }

        // Punch a hole in the overlay file to reclaim host disk space.
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::AsRawFd;
            let fd = self.overlay.as_raw_fd();
            // SAFETY: fallocate with FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE is safe
            // on a valid fd with valid offset/len.
            let ret = unsafe {
                libc::fallocate(
                    fd,
                    libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
                    offset as i64,
                    len as i64,
                )
            };
            if ret != 0 {
                // Non-fatal: bitmap is already cleared so reads stay correct, we just
                // don't reclaim host space. Log so silent leakage on filesystems
                // without PUNCH_HOLE support (NFS, tmpfs, ext3) shows up.
                let err = std::io::Error::last_os_error();
                warn!("overlay discard: hole punch failed offset={offset} len={len}: {err}");
            }
        }

        Ok(())
    }

    /// Write a delta file containing only dirty blocks from this overlay.
    pub fn write_delta(
        &mut self,
        delta_path: &std::path::Path,
    ) -> Result<delta::DeltaStats, delta::DeltaError> {
        delta::write_delta(&mut self.overlay, &self.bitmap, delta_path)
    }

    /// Bake every dirty block into `base_path` in place, sync base, clear
    /// the bitmap. MUTATES base.ext4 — only safe when no other VMM is
    /// concurrently reading it. Used by `CreateSnapshot { flatten: true }`.
    /// Errors loud if base size doesn't match `block_size * total_blocks`
    /// rather than silently extending/truncating the disk image.
    ///
    /// No CRC validation on the overlay→base copy: it's a same-process,
    /// page-cache-warm transfer, so integrity depends on the overlay being
    /// trustworthy at call time (which it is in the build-then-snapshot
    /// flow, where the overlay was just written by this engine).
    ///
    /// CALLER MUST ensure the owning VM is paused — concurrent guest I/O
    /// against the overlay during this call can produce inconsistent base
    /// content. `create_snapshot` already gates this on PatchVM(paused).
    pub fn apply_overlay_to_base(
        &mut self,
        base_path: &std::path::Path,
    ) -> Result<(), OverlayIoError> {
        // Second FD onto the same base file (engine already holds an RO one).
        // Both share the page cache and the VM is paused, so writes through
        // this FD become visible via the RO FD after `sync_all` below.
        let mut base = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(base_path)
            .map_err(OverlayIoError::FlattenBaseOpen)?;

        let block_size = self.bitmap.block_size();
        let expected_size = u64::from(block_size) * self.bitmap.total_blocks();
        let actual_size = base
            .metadata()
            .map_err(OverlayIoError::FlattenBaseOpen)?
            .len();
        if actual_size != expected_size {
            return Err(OverlayIoError::FlattenBaseSizeMismatch {
                expected: expected_size,
                actual: actual_size,
            });
        }
        // Positional I/O (pread/pwrite): no seek syscall per block, halves
        // the syscall count for large flattens and makes the intent obvious.
        use std::os::unix::fs::FileExt;
        let mut buf = vec![0u8; block_size as usize];

        for block_idx in self.bitmap.iter_dirty() {
            let offset = block_idx * u64::from(block_size);
            self.overlay
                .read_exact_at(&mut buf, offset)
                .map_err(OverlayIoError::FlattenOverlayRead)?;
            base.write_all_at(&buf, offset)
                .map_err(OverlayIoError::FlattenBaseWrite)?;
        }

        base.sync_all().map_err(OverlayIoError::FlattenBaseSync)?;
        self.bitmap.clear();
        Ok(())
    }

    /// Read from the appropriate source (base or overlay) based on the dirty bitmap.
    pub fn read(
        &mut self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
    ) -> Result<u32, OverlayIoError> {
        match self.bitmap.is_range_uniform(offset, count) {
            Some(false) => {
                // All clean — read entirely from base.
                self.read_from_base(offset, mem, addr, count)
            }
            Some(true) => {
                // All dirty — read entirely from overlay.
                self.read_from_overlay(offset, mem, addr, count)
            }
            None => {
                // Mixed — split into contiguous runs from the same source.
                self.read_mixed(offset, mem, addr, count)
            }
        }
    }

    /// Write to the overlay and mark blocks as dirty.
    ///
    /// Copy-on-write semantics: when a write would only partially cover a
    /// currently-clean block, the rest of the block is read from `base` and
    /// written to `overlay` first. Without this copy-up step the unwritten
    /// portion of the block would silently read back as zeros (the overlay
    /// file is sparse) instead of the original base data.
    ///
    /// Three cases of interest, all relative to the dirty-bitmap block size:
    ///
    /// - The first block is partially written (write starts mid-block) and is
    ///   currently clean → copy-up that block from base.
    /// - The last block is partially written (write ends mid-block) and is
    ///   currently clean → copy-up that block from base.
    /// - Middle blocks fully covered by the write don't need copy-up — they
    ///   are overwritten in their entirety.
    ///
    /// When the write covers a single partial block, the first-block branch
    /// handles it; the last-block branch is skipped because it would refer
    /// to the same block.
    pub fn write(
        &mut self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
    ) -> Result<u32, OverlayIoError> {
        let block_size = u64::from(self.bitmap.block_size());
        let count_u64 = u64::from(count);
        let end_offset = offset + count_u64;

        // A block needs copy-up if the write doesn't fully cover it AND
        // the block is currently clean. "Fully covered" means the write
        // starts at-or-before the block start and ends at-or-after the
        // block end — anything else leaves bytes unwritten in the overlay.
        let first_block_idx = offset / block_size;
        let first_block_start = first_block_idx * block_size;
        let first_block_end = first_block_start + block_size;
        let first_fully_covered =
            offset == first_block_start && end_offset >= first_block_end;
        if !first_fully_covered && !self.bitmap.is_set(first_block_idx) {
            self.copy_up_block(first_block_start, block_size)?;
        }

        // Last touched block, but only when it's a different block from the
        // first (single-block writes are already handled above).
        if count_u64 > 0 {
            let last_block_idx = (end_offset - 1) / block_size;
            if last_block_idx != first_block_idx {
                let last_block_start = last_block_idx * block_size;
                let last_block_end = last_block_start + block_size;
                // The write necessarily reaches into this block, so the
                // start side is covered; the only unwritten portion would
                // be a tail past `end_offset`.
                if end_offset < last_block_end && !self.bitmap.is_set(last_block_idx) {
                    self.copy_up_block(last_block_start, block_size)?;
                }
            }
        }

        // Apply the actual partial / full write.
        self.overlay
            .seek(SeekFrom::Start(offset))
            .map_err(OverlayIoError::OverlaySeek)?;
        mem.get_slice(addr, count as usize)
            .and_then(|slice| Ok(self.overlay.write_all_volatile(&slice)?))
            .map_err(OverlayIoError::OverlayWriteTransfer)?;

        self.bitmap.set(offset, count);
        Ok(count)
    }

    /// Read `block_size` bytes from `base` at `block_offset` and write them
    /// to `overlay` at the same offset. Used by `write` to lift unwritten
    /// portions of partially-written blocks before applying the new data.
    ///
    /// `base` and `overlay` are the same logical size (enforced at engine
    /// construction), so `block_offset + block_size` is always within range.
    fn copy_up_block(
        &mut self,
        block_offset: u64,
        block_size: u64,
    ) -> Result<(), OverlayIoError> {
        let block_size = block_size as usize;
        let mut buf = vec![0u8; block_size];

        self.base
            .seek(SeekFrom::Start(block_offset))
            .map_err(OverlayIoError::BaseSeek)?;
        // read_exact: base has been size-checked at engine construction, so
        // any short read here is a hard error rather than EOF-at-tail.
        self.base
            .read_exact(&mut buf)
            .map_err(OverlayIoError::BaseHostRead)?;

        self.overlay
            .seek(SeekFrom::Start(block_offset))
            .map_err(OverlayIoError::OverlaySeek)?;
        self.overlay
            .write_all(&buf)
            .map_err(OverlayIoError::OverlayHostWrite)?;

        Ok(())
    }

    /// Flush the overlay file to disk. Base is read-only and never needs flushing.
    pub fn flush(&mut self) -> Result<(), OverlayIoError> {
        self.overlay
            .flush()
            .map_err(OverlayIoError::OverlayFlush)?;
        self.overlay
            .sync_all()
            .map_err(OverlayIoError::OverlaySync)
    }

    /// Read a contiguous range from the base file.
    fn read_from_base(
        &mut self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
    ) -> Result<u32, OverlayIoError> {
        self.base
            .seek(SeekFrom::Start(offset))
            .map_err(OverlayIoError::BaseSeek)?;
        mem.get_slice(addr, count as usize)
            .and_then(|mut slice| Ok(self.base.read_exact_volatile(&mut slice)?))
            .map_err(OverlayIoError::BaseTransfer)?;
        Ok(count)
    }

    /// Read a contiguous range from the overlay file.
    fn read_from_overlay(
        &mut self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
    ) -> Result<u32, OverlayIoError> {
        self.overlay
            .seek(SeekFrom::Start(offset))
            .map_err(OverlayIoError::OverlaySeek)?;
        mem.get_slice(addr, count as usize)
            .and_then(|mut slice| Ok(self.overlay.read_exact_volatile(&mut slice)?))
            .map_err(OverlayIoError::OverlayReadTransfer)?;
        Ok(count)
    }

    /// Handle a read that spans both dirty and clean blocks.
    ///
    /// Splits the range into contiguous runs from the same source and reads each
    /// run separately. This is the slow path — most reads hit the fast path above.
    fn read_mixed(
        &mut self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
    ) -> Result<u32, OverlayIoError> {
        let block_size = u64::from(self.bitmap.block_size());
        let end_offset = offset + u64::from(count);

        let mut current_offset = offset;
        let mut current_addr = addr;

        while current_offset < end_offset {
            let current_block = current_offset / block_size;
            let is_dirty = self.bitmap.is_set(current_block);

            // Find the end of this contiguous run of same-source blocks.
            let mut run_end_block = current_block + 1;
            while run_end_block * block_size < end_offset {
                if self.bitmap.is_set(run_end_block) != is_dirty {
                    break;
                }
                run_end_block += 1;
            }

            // Calculate the byte range for this run, clamped to the request bounds.
            let run_byte_start = current_offset;
            let run_byte_end = (run_end_block * block_size).min(end_offset);
            let run_len = (run_byte_end - run_byte_start) as u32;

            if is_dirty {
                self.read_from_overlay(run_byte_start, mem, current_addr, run_len)?;
            } else {
                self.read_from_base(run_byte_start, mem, current_addr, run_len)?;
            }

            current_offset = run_byte_end;
            current_addr = GuestAddress(current_addr.0 + u64::from(run_len));
        }

        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::devices::virtio::block::virtio::io::dirty_bitmap::DEFAULT_BLOCK_SIZE;
    use crate::vmm_config::machine_config::HugePageConfig;
    use crate::vstate::memory;
    use crate::vstate::memory::{Bytes, GuestRegionMmapExt};

    const FILE_LEN: u64 = 16384; // 4 blocks of 4KB
    const MEM_LEN: usize = 16384;

    fn create_mem() -> GuestMemoryMmap {
        GuestMemoryMmap::from_regions(
            memory::anonymous(
                [(GuestAddress(0), MEM_LEN)].into_iter(),
                true,
                HugePageConfig::None,
            )
            .unwrap()
            .into_iter()
            .map(|region| GuestRegionMmapExt::dram_from_mmap_region(region, 0))
            .collect(),
        )
        .unwrap()
    }

    fn create_base_file(data: &[u8]) -> File {
        let f = TempFile::new().unwrap().into_file();
        use std::io::Write;
        (&f).write_all(data).unwrap();
        f
    }

    fn create_overlay_file(size: u64) -> File {
        let f = TempFile::new().unwrap().into_file();
        f.set_len(size).unwrap();
        f
    }

    fn create_engine(base_data: &[u8]) -> OverlayFileEngine {
        let base = create_base_file(base_data);
        let overlay = create_overlay_file(base_data.len() as u64);
        OverlayFileEngine::from_files(
            base,
            overlay,
            base_data.len() as u64,
            DEFAULT_BLOCK_SIZE,
            None,
        )
        .unwrap()
    }

    #[test]
    fn test_read_from_base_only() {
        let base_data: Vec<u8> = (0..FILE_LEN).map(|i| (i % 251) as u8).collect();
        let mut engine = create_engine(&base_data);
        let mem = create_mem();

        // Read first 512 bytes — should come from base.
        engine.read(0, &mem, GuestAddress(0), 512).unwrap();

        let mut buf = vec![0u8; 512];
        mem.read_slice(&mut buf, GuestAddress(0)).unwrap();
        assert_eq!(buf, &base_data[..512]);
    }

    #[test]
    fn test_open_without_bitmap_reads_the_overlays_written_blocks() {
        use std::os::unix::fs::FileExt;
        const BLOCK: u64 = DEFAULT_BLOCK_SIZE as u64;
        let base_data = vec![0xAA_u8; FILE_LEN as usize];
        let base = create_base_file(&base_data);
        // A restored overlay: sparse, with only the guest-written blocks present.
        let overlay = create_overlay_file(FILE_LEN);
        overlay.write_all_at(&vec![0xBB_u8; BLOCK as usize], BLOCK).unwrap();
        overlay.write_all_at(&vec![0xCC_u8; BLOCK as usize], 3 * BLOCK).unwrap();
        overlay.sync_all().unwrap();

        let mut engine =
            OverlayFileEngine::from_files(base, overlay, FILE_LEN, DEFAULT_BLOCK_SIZE, None)
                .unwrap();
        assert_eq!(engine.bitmap().dirty_count(), 2);

        let mem = create_mem();
        let mut buf = vec![0u8; BLOCK as usize];
        for (block, want) in [(0u64, 0xAA_u8), (1, 0xBB), (2, 0xAA), (3, 0xCC)] {
            engine
                .read(block * BLOCK, &mem, GuestAddress(0), DEFAULT_BLOCK_SIZE)
                .unwrap();
            mem.read_slice(&mut buf, GuestAddress(0)).unwrap();
            assert!(
                buf.iter().all(|&b| b == want),
                "block {block} must read {want:#x}"
            );
        }
    }

    #[test]
    fn test_write_then_read_from_overlay() {
        let base_data = vec![0xAA_u8; FILE_LEN as usize];
        let mut engine = create_engine(&base_data);

        // Write different data to overlay.
        let write_data = vec![0xBB_u8; 512];
        let mem = create_mem();
        mem.write(&write_data, GuestAddress(0)).unwrap();
        engine.write(0, &mem, GuestAddress(0), 512).unwrap();

        // Read back — should get overlay data, not base.
        let mem = create_mem();
        engine.read(0, &mem, GuestAddress(0), 512).unwrap();

        let mut buf = vec![0u8; 512];
        mem.read_slice(&mut buf, GuestAddress(0)).unwrap();
        assert_eq!(buf, write_data);
    }

    #[test]
    fn test_base_not_modified_after_write() {
        let base_data = vec![0xAA_u8; FILE_LEN as usize];
        let mut engine = create_engine(&base_data);

        // Write to overlay.
        let write_data = vec![0xBB_u8; 4096];
        let mem = create_mem();
        mem.write(&write_data, GuestAddress(0)).unwrap();
        engine.write(0, &mem, GuestAddress(0), 4096).unwrap();

        // Read from base directly — should still be original data.
        let mem = create_mem();
        engine.read_from_base(0, &mem, GuestAddress(0), 512).unwrap();

        let mut buf = vec![0u8; 512];
        mem.read_slice(&mut buf, GuestAddress(0)).unwrap();
        assert_eq!(buf, vec![0xAA_u8; 512]);
    }

    #[test]
    fn test_mixed_read() {
        let base_data = vec![0xAA_u8; FILE_LEN as usize];
        let mut engine = create_engine(&base_data);

        // Write to block 0 only (first 4KB).
        let write_data = vec![0xBB_u8; 4096];
        let mem = create_mem();
        mem.write(&write_data, GuestAddress(0)).unwrap();
        engine.write(0, &mem, GuestAddress(0), 4096).unwrap();

        // Read 8KB spanning block 0 (dirty) and block 1 (clean).
        let mem = create_mem();
        engine.read(0, &mem, GuestAddress(0), 8192).unwrap();

        let mut buf = vec![0u8; 8192];
        mem.read_slice(&mut buf, GuestAddress(0)).unwrap();

        // First 4KB should be overlay data (0xBB).
        assert_eq!(&buf[..4096], &vec![0xBB_u8; 4096]);
        // Second 4KB should be base data (0xAA).
        assert_eq!(&buf[4096..8192], &vec![0xAA_u8; 4096]);
    }

    #[test]
    fn test_write_updates_bitmap() {
        let base_data = vec![0u8; FILE_LEN as usize];
        let mut engine = create_engine(&base_data);

        assert_eq!(engine.bitmap().dirty_count(), 0);

        let mem = create_mem();
        engine.write(0, &mem, GuestAddress(0), 512).unwrap();
        assert_eq!(engine.bitmap().dirty_count(), 1);

        // Write to a different block.
        engine.write(4096, &mem, GuestAddress(0), 512).unwrap();
        assert_eq!(engine.bitmap().dirty_count(), 2);
    }

    #[test]
    fn test_flush() {
        let base_data = vec![0u8; FILE_LEN as usize];
        let mut engine = create_engine(&base_data);
        // Flush should succeed even with no writes.
        engine.flush().unwrap();
    }

    #[test]
    fn test_read_at_offset() {
        let base_data: Vec<u8> = (0..FILE_LEN).map(|i| (i % 251) as u8).collect();
        let mut engine = create_engine(&base_data);
        let mem = create_mem();

        let offset = 4096u64;
        let count = 512u32;
        engine
            .read(offset, &mem, GuestAddress(0), count)
            .unwrap();

        let mut buf = vec![0u8; count as usize];
        mem.read_slice(&mut buf, GuestAddress(0)).unwrap();
        assert_eq!(buf, &base_data[offset as usize..(offset as usize + count as usize)]);
    }

    #[test]
    fn test_write_at_offset_then_read() {
        let base_data = vec![0xAA_u8; FILE_LEN as usize];
        let mut engine = create_engine(&base_data);

        // Write at offset 4096 (block 1).
        let write_data = vec![0xCC_u8; 512];
        let mem = create_mem();
        mem.write(&write_data, GuestAddress(0)).unwrap();
        engine.write(4096, &mem, GuestAddress(0), 512).unwrap();

        // Read back from same offset.
        let mem = create_mem();
        engine.read(4096, &mem, GuestAddress(0), 512).unwrap();

        let mut buf = vec![0u8; 512];
        mem.read_slice(&mut buf, GuestAddress(0)).unwrap();
        assert_eq!(buf, write_data);

        // Block 0 should still be base data.
        let mem = create_mem();
        engine.read(0, &mem, GuestAddress(0), 512).unwrap();

        let mut buf = vec![0u8; 512];
        mem.read_slice(&mut buf, GuestAddress(0)).unwrap();
        assert_eq!(buf, vec![0xAA_u8; 512]);
    }

    #[test]
    fn test_overwrite_same_block() {
        let base_data = vec![0xAA_u8; FILE_LEN as usize];
        let mut engine = create_engine(&base_data);

        // First write.
        let data1 = vec![0xBB_u8; 512];
        let mem = create_mem();
        mem.write(&data1, GuestAddress(0)).unwrap();
        engine.write(0, &mem, GuestAddress(0), 512).unwrap();

        // Overwrite same location.
        let data2 = vec![0xCC_u8; 512];
        let mem = create_mem();
        mem.write(&data2, GuestAddress(0)).unwrap();
        engine.write(0, &mem, GuestAddress(0), 512).unwrap();

        // Should get the second write.
        let mem = create_mem();
        engine.read(0, &mem, GuestAddress(0), 512).unwrap();

        let mut buf = vec![0u8; 512];
        mem.read_slice(&mut buf, GuestAddress(0)).unwrap();
        assert_eq!(buf, data2);

        // Bitmap should still show 1 dirty block.
        assert_eq!(engine.bitmap().dirty_count(), 1);
    }

    /// Sub-block write must copy the unwritten portion of the block from base.
    ///
    /// Without copy-up, the overlay file is sparse beyond the written bytes
    /// and the reader incorrectly returns zeros for the unwritten range —
    /// silent data corruption.
    #[test]
    fn test_partial_write_copies_up_unwritten_prefix_of_block() {
        let base_data = vec![0xAA_u8; FILE_LEN as usize];
        let mut engine = create_engine(&base_data);

        // Write 512 bytes of 0xBB to the START of block 0 (offset 0).
        let mem = create_mem();
        mem.write(&vec![0xBB_u8; 512], GuestAddress(0)).unwrap();
        engine.write(0, &mem, GuestAddress(0), 512).unwrap();

        // Read the next 3584 bytes — still inside block 0 — should still be
        // 0xAA from base, not 0x00 from a sparse overlay file.
        let mem = create_mem();
        engine.read(512, &mem, GuestAddress(0), 3584).unwrap();
        let mut buf = vec![0u8; 3584];
        mem.read_slice(&mut buf, GuestAddress(0)).unwrap();
        assert_eq!(buf, vec![0xAA_u8; 3584]);
    }

    /// Symmetric case: write the END of a block, read the prefix back.
    /// The prefix must come from base, not the sparse overlay.
    #[test]
    fn test_partial_write_copies_up_unwritten_suffix_of_block() {
        let base_data = vec![0xAA_u8; FILE_LEN as usize];
        let mut engine = create_engine(&base_data);

        // Write the last 512 bytes of block 0 (offset 3584..4096).
        let mem = create_mem();
        mem.write(&vec![0xBB_u8; 512], GuestAddress(0)).unwrap();
        engine.write(3584, &mem, GuestAddress(0), 512).unwrap();

        // Read the first 3584 bytes of block 0 — should be 0xAA from base.
        let mem = create_mem();
        engine.read(0, &mem, GuestAddress(0), 3584).unwrap();
        let mut buf = vec![0u8; 3584];
        mem.read_slice(&mut buf, GuestAddress(0)).unwrap();
        assert_eq!(buf, vec![0xAA_u8; 3584]);
    }

    /// Write spans two blocks, partial at both ends. Both unwritten edges
    /// must be copied up from base.
    #[test]
    fn test_partial_write_spanning_two_blocks_copies_up_both_edges() {
        // Use distinguishable base data so a stray copy-up failure is obvious.
        let mut base_data = vec![0u8; FILE_LEN as usize];
        for (i, b) in base_data.iter_mut().enumerate() {
            // Block 0 = 0xAA, block 1 = 0xCC, rest don't matter.
            *b = if i < 4096 { 0xAA } else { 0xCC };
        }
        let mut engine = create_engine(&base_data);

        // Write 4096 bytes of 0xBB starting at offset 2048 — covers the
        // second half of block 0 and the first half of block 1.
        let mem = create_mem();
        mem.write(&vec![0xBB_u8; 4096], GuestAddress(0)).unwrap();
        engine.write(2048, &mem, GuestAddress(0), 4096).unwrap();

        // First half of block 0 must still be 0xAA.
        let mem = create_mem();
        engine.read(0, &mem, GuestAddress(0), 2048).unwrap();
        let mut buf = vec![0u8; 2048];
        mem.read_slice(&mut buf, GuestAddress(0)).unwrap();
        assert_eq!(buf, vec![0xAA_u8; 2048], "block 0 prefix corrupted");

        // Second half of block 1 must still be 0xCC.
        let mem = create_mem();
        engine.read(6144, &mem, GuestAddress(0), 2048).unwrap();
        let mut buf = vec![0u8; 2048];
        mem.read_slice(&mut buf, GuestAddress(0)).unwrap();
        assert_eq!(buf, vec![0xCC_u8; 2048], "block 1 suffix corrupted");
    }

    /// A full-block-aligned write doesn't need copy-up; sanity check that
    /// the fast path is unchanged.
    #[test]
    fn test_full_block_write_does_not_corrupt_neighbours() {
        let mut base_data = vec![0u8; FILE_LEN as usize];
        for (i, b) in base_data.iter_mut().enumerate() {
            *b = match i / 4096 {
                0 => 0xAA,
                1 => 0xBB,
                2 => 0xCC,
                _ => 0xDD,
            };
        }
        let mut engine = create_engine(&base_data);

        // Overwrite block 1 entirely with 0xEE.
        let mem = create_mem();
        mem.write(&vec![0xEE_u8; 4096], GuestAddress(0)).unwrap();
        engine.write(4096, &mem, GuestAddress(0), 4096).unwrap();

        // Block 0 still 0xAA, block 1 now 0xEE, block 2 still 0xCC.
        let mem = create_mem();
        engine.read(0, &mem, GuestAddress(0), 12288).unwrap();
        let mut buf = vec![0u8; 12288];
        mem.read_slice(&mut buf, GuestAddress(0)).unwrap();
        assert_eq!(&buf[0..4096], &vec![0xAA_u8; 4096][..], "block 0");
        assert_eq!(&buf[4096..8192], &vec![0xEE_u8; 4096][..], "block 1");
        assert_eq!(&buf[8192..12288], &vec![0xCC_u8; 4096][..], "block 2");
    }

    #[test]
    fn test_apply_overlay_to_base_bakes_dirty_blocks_and_clears_bitmap() {
        use std::io::Read;

        const BLOCK: usize = DEFAULT_BLOCK_SIZE as usize;
        const N_BLOCKS: usize = 4;
        const SIZE: usize = BLOCK * N_BLOCKS;

        // Base file filled with 0xAA. Keep TempFile alive so path stays valid.
        let base_tmp = TempFile::new().unwrap();
        std::fs::write(base_tmp.as_path(), vec![0xAA_u8; SIZE]).unwrap();

        // Overlay file with distinct content at blocks 1 and 3.
        let overlay_tmp = TempFile::new().unwrap();
        let mut overlay_bytes = vec![0u8; SIZE];
        overlay_bytes[BLOCK..2 * BLOCK].fill(0x11);
        overlay_bytes[3 * BLOCK..4 * BLOCK].fill(0x33);
        std::fs::write(overlay_tmp.as_path(), &overlay_bytes).unwrap();

        // Bitmap claiming blocks 1 and 3 are dirty (live in overlay).
        let mut bitmap = DirtyBitmap::new(SIZE as u64, DEFAULT_BLOCK_SIZE).unwrap();
        bitmap.set(BLOCK as u64, DEFAULT_BLOCK_SIZE);
        bitmap.set(3 * BLOCK as u64, DEFAULT_BLOCK_SIZE);

        let base = File::open(base_tmp.as_path()).unwrap();
        let overlay = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(overlay_tmp.as_path())
            .unwrap();
        let mut engine = OverlayFileEngine::from_files(
            base,
            overlay,
            SIZE as u64,
            DEFAULT_BLOCK_SIZE,
            Some(bitmap),
        )
        .unwrap();

        engine.apply_overlay_to_base(base_tmp.as_path()).unwrap();

        // Bitmap fully cleared.
        assert_eq!(engine.bitmap().dirty_count(), 0);

        // Base on disk now holds the overlay's dirty content at blocks 1, 3
        // and the original 0xAA elsewhere.
        let mut baked = vec![0u8; SIZE];
        File::open(base_tmp.as_path())
            .unwrap()
            .read_exact(&mut baked)
            .unwrap();
        assert!(baked[..BLOCK].iter().all(|&b| b == 0xAA), "block 0 clean");
        assert!(
            baked[BLOCK..2 * BLOCK].iter().all(|&b| b == 0x11),
            "block 1 baked"
        );
        assert!(
            baked[2 * BLOCK..3 * BLOCK].iter().all(|&b| b == 0xAA),
            "block 2 clean"
        );
        assert!(
            baked[3 * BLOCK..4 * BLOCK].iter().all(|&b| b == 0x33),
            "block 3 baked"
        );
    }

    #[test]
    fn test_apply_overlay_to_base_idempotent() {
        const BLOCK: usize = DEFAULT_BLOCK_SIZE as usize;
        const N_BLOCKS: usize = 4;
        const SIZE: usize = BLOCK * N_BLOCKS;

        let base_tmp = TempFile::new().unwrap();
        std::fs::write(base_tmp.as_path(), vec![0xAA_u8; SIZE]).unwrap();
        let overlay_tmp = TempFile::new().unwrap();
        // A never-written overlay is all holes; allocated zeros would count as
        // guest writes.
        std::fs::File::create(overlay_tmp.as_path())
            .unwrap()
            .set_len(SIZE as u64)
            .unwrap();

        let base = File::open(base_tmp.as_path()).unwrap();
        let overlay = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(overlay_tmp.as_path())
            .unwrap();
        // Fresh engine with empty bitmap (no dirty blocks).
        let mut engine = OverlayFileEngine::from_files(
            base,
            overlay,
            SIZE as u64,
            DEFAULT_BLOCK_SIZE,
            None,
        )
        .unwrap();

        // First call: empty bitmap, no writes.
        engine.apply_overlay_to_base(base_tmp.as_path()).unwrap();
        // Second call on the now-flat engine: still a no-op, must succeed.
        engine.apply_overlay_to_base(base_tmp.as_path()).unwrap();
        assert_eq!(engine.bitmap().dirty_count(), 0);
    }

    #[test]
    fn test_apply_overlay_to_base_rejects_size_mismatch() {
        const BLOCK: usize = DEFAULT_BLOCK_SIZE as usize;
        const N_BLOCKS: usize = 4;
        const SIZE: usize = BLOCK * N_BLOCKS;

        let base_tmp = TempFile::new().unwrap();
        std::fs::write(base_tmp.as_path(), vec![0u8; SIZE - 1]).unwrap(); // too small by 1 byte

        let overlay_tmp = TempFile::new().unwrap();
        std::fs::write(overlay_tmp.as_path(), vec![0u8; SIZE]).unwrap();

        let mut bitmap = DirtyBitmap::new(SIZE as u64, DEFAULT_BLOCK_SIZE).unwrap();
        bitmap.set(BLOCK as u64, DEFAULT_BLOCK_SIZE);

        let base = File::open(base_tmp.as_path()).unwrap();
        let overlay = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(overlay_tmp.as_path())
            .unwrap();
        let mut engine = OverlayFileEngine::from_files(
            base,
            overlay,
            SIZE as u64,
            DEFAULT_BLOCK_SIZE,
            Some(bitmap),
        )
        .unwrap();

        let result = engine.apply_overlay_to_base(base_tmp.as_path());
        match result {
            Err(OverlayIoError::FlattenBaseSizeMismatch { expected, actual }) => {
                assert_eq!(expected, SIZE as u64);
                assert_eq!(actual, (SIZE - 1) as u64);
            }
            other => panic!("expected FlattenBaseSizeMismatch, got {other:?}"),
        }
    }
}

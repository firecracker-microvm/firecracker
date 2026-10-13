// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Merged, read-only view of a stack of sparse snapshot memory layers.
//!
//! Layer 0 is the root (usually a Full snapshot memory file); every following
//! layer is a Diff snapshot memory file taken from a VM restored from the
//! layer before it. All layers have the size of guest memory, and a Diff only
//! contains data for the pages that were dirty - every other page is a hole.
//!
//! The merged view is built with the MMU rather than by copying: we reserve
//! one read-only anonymous area the size of guest memory and then, from the
//! oldest layer to the newest, `mmap(MAP_FIXED)` every data extent of the
//! layer over the matching range. Afterwards each page of the area is backed
//! by the newest layer that has data for it (or by the anonymous zero page if
//! no layer has, which matches what a hole in the root reads as).

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::undocumented_unsafe_blocks,
    dead_code
)]

use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::{io, ptr};

/// A data extent `[start, end)` of a sparse file, in bytes.
pub type Extent = (u64, u64);

/// Returns the data extents of `file`, in increasing order.
pub fn data_extents(file: &File) -> io::Result<Vec<Extent>> {
    let fd = file.as_raw_fd();
    let len = file.metadata()?.len() as i64;
    let mut extents = Vec::new();
    let mut offset: i64 = 0;

    while offset < len {
        // SAFETY: lseek on a valid fd has no memory safety requirements.
        let data = unsafe { libc::lseek(fd, offset, libc::SEEK_DATA) };
        if data < 0 {
            let err = io::Error::last_os_error();
            // ENXIO: no more data past `offset`.
            if err.raw_os_error() == Some(libc::ENXIO) {
                break;
            }
            return Err(err);
        }
        // SAFETY: as above.
        let hole = unsafe { libc::lseek(fd, data, libc::SEEK_HOLE) };
        if hole < 0 {
            return Err(io::Error::last_os_error());
        }
        extents.push((data as u64, hole as u64));
        offset = hole;
    }

    Ok(extents)
}

/// A read-only mapping presenting a stack of layers as one memory image.
#[derive(Debug)]
pub struct LayeredMemory {
    base: *mut u8,
    size: usize,
    /// Number of `mmap` calls made to build the view (one per data extent).
    pub extent_count: usize,
    // The mappings keep the files referenced, but we hold on to them anyway so
    // that their lifetime is explicit.
    _layers: Vec<File>,
}

impl LayeredMemory {
    /// Builds the merged view of `layers`, ordered from oldest (root) to newest.
    pub fn new(layers: Vec<File>) -> io::Result<Self> {
        let size = match layers.first() {
            Some(root) => root.metadata()?.len() as usize,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "at least one layer is required",
                ));
            }
        };
        if size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "root layer is empty",
            ));
        }
        for (i, layer) in layers.iter().enumerate() {
            let len = layer.metadata()?.len() as usize;
            if len != size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("layer {i} is {len} bytes, but the root layer is {size} bytes"),
                ));
            }
        }

        // SAFETY: sysconf has no memory safety requirements.
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;

        // SAFETY: a fresh anonymous mapping; the kernel picks the address.
        let base = unsafe {
            libc::mmap(
                ptr::null_mut(),
                size,
                libc::PROT_READ,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }

        let mut mem = Self {
            base: base.cast(),
            size,
            extent_count: 0,
            _layers: Vec::new(),
        };

        for (i, layer) in layers.iter().enumerate() {
            for (start, end) in data_extents(layer)? {
                // SEEK_HOLE may report the end of file as the end of the last
                // extent; the file size is page aligned for guest memory, but
                // be strict anyway: overlaying a partial page would hide the
                // parent's data for the rest of that page.
                if start % page_size != 0 || end % page_size != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "layer {i}: data extent [{start:#x}, {end:#x}) is not aligned to the \
                             {page_size}-byte page size"
                        ),
                    ));
                }
                // SAFETY: [start, end) lies within the reserved area because
                // every layer has exactly `size` bytes, and we own the area.
                let ret = unsafe {
                    libc::mmap(
                        mem.base.add(start as usize).cast(),
                        (end - start) as usize,
                        libc::PROT_READ,
                        libc::MAP_PRIVATE | libc::MAP_FIXED,
                        layer.as_raw_fd(),
                        start as i64,
                    )
                };
                if ret == libc::MAP_FAILED {
                    let err = io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::ENOMEM) {
                        return Err(io::Error::new(
                            io::ErrorKind::OutOfMemory,
                            format!(
                                "mapping layer {i} failed after {} extents; the chain is probably \
                                 too fragmented for vm.max_map_count - squash it: {err}",
                                mem.extent_count
                            ),
                        ));
                    }
                    return Err(err);
                }
                mem.extent_count += 1;
            }
        }

        mem._layers = layers;
        Ok(mem)
    }

    /// Start of the merged view.
    pub fn as_ptr(&self) -> *mut u8 {
        self.base
    }

    /// Size of the merged view in bytes (the guest memory size).
    pub fn len(&self) -> usize {
        self.size
    }

    /// The merged view as a slice.
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: the area is mapped readable for `size` bytes while `self` lives.
        unsafe { std::slice::from_raw_parts(self.base, self.size) }
    }
}

impl Drop for LayeredMemory {
    fn drop(&mut self) {
        // SAFETY: we own the area and nothing borrows it past `self`.
        unsafe {
            libc::munmap(self.base.cast(), self.size);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::FileExt;

    use vmm_sys_util::tempfile::TempFile;

    use super::*;

    const PAGE: usize = 4096;

    /// Tiny deterministic PRNG so the test needs no extra dependencies.
    struct XorShift(u64);
    impl XorShift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    fn page_with(fill: u8, tag: u64) -> Vec<u8> {
        let mut page = vec![fill; PAGE];
        page[..8].copy_from_slice(&tag.to_le_bytes());
        page
    }

    /// Creates a sparse layer of `pages` pages and writes `writes` into it.
    fn layer(pages: usize, writes: &[(usize, Vec<u8>)]) -> TempFile {
        let f = TempFile::new().unwrap();
        f.as_file().set_len((pages * PAGE) as u64).unwrap();
        for (page, data) in writes {
            f.as_file()
                .write_all_at(data, (page * PAGE) as u64)
                .unwrap();
        }
        f
    }

    fn open(f: &TempFile) -> File {
        File::open(f.as_path()).unwrap()
    }

    #[test]
    fn test_data_extents() {
        let f = layer(
            16,
            &[
                (1, page_with(1, 1)),
                (2, page_with(2, 2)),
                (9, page_with(9, 9)),
            ],
        );
        let extents = data_extents(f.as_file()).unwrap();
        // Filesystems may report data at a coarser granularity, but the pages
        // we wrote must all be covered and the first page must be a hole on
        // any filesystem with 4K blocks.
        let covered = |p: usize| {
            extents
                .iter()
                .any(|&(s, e)| s <= (p * PAGE) as u64 && ((p + 1) * PAGE) as u64 <= e)
        };
        assert!(covered(1) && covered(2) && covered(9));
        assert!(!covered(0), "extents: {extents:x?}");
    }

    #[test]
    fn test_random_stacks_match_flattened_image() {
        let mut rng = XorShift(0x9e37_79b9_7f4a_7c15);

        for round in 0..20 {
            let pages = 1 + rng.below(256);
            let depth = 1 + rng.below(8);
            let mut expected = vec![0u8; pages * PAGE];
            let mut files = Vec::new();

            for level in 0..depth {
                let mut writes = Vec::new();
                if level == 0 && rng.below(2) == 0 {
                    // Dense root, like a Full snapshot.
                    for p in 0..pages {
                        writes.push((p, page_with(0xaa, (p as u64) << 8)));
                    }
                } else {
                    for _ in 0..rng.below(pages + 1) {
                        let p = rng.below(pages);
                        // Every so often the dirty page is all zeros: it must
                        // still shadow older layers.
                        let data = if rng.below(8) == 0 {
                            vec![0u8; PAGE]
                        } else {
                            page_with(
                                level as u8,
                                ((round as u64) << 32) | ((level as u64) << 16) | p as u64,
                            )
                        };
                        writes.push((p, data));
                    }
                }
                for (p, data) in &writes {
                    expected[p * PAGE..(p + 1) * PAGE].copy_from_slice(data);
                }
                files.push(layer(pages, &writes));
            }

            let mem = LayeredMemory::new(files.iter().map(open).collect()).unwrap();
            assert_eq!(mem.len(), pages * PAGE);
            for p in 0..pages {
                assert_eq!(
                    &mem.as_slice()[p * PAGE..(p + 1) * PAGE],
                    &expected[p * PAGE..(p + 1) * PAGE],
                    "round {round}: page {p} of {pages}, depth {depth}"
                );
            }
        }
    }

    #[test]
    fn test_zero_page_shadows_parent() {
        let root = layer(4, &[(0, page_with(7, 7)), (1, page_with(7, 8))]);
        let child = layer(4, &[(1, vec![0u8; PAGE])]);
        let mem = LayeredMemory::new(vec![open(&root), open(&child)]).unwrap();
        assert_eq!(&mem.as_slice()[..PAGE], &page_with(7, 7)[..]);
        assert!(mem.as_slice()[PAGE..2 * PAGE].iter().all(|&b| b == 0));
        assert!(mem.as_slice()[2 * PAGE..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_rejects_bad_stacks() {
        assert!(LayeredMemory::new(vec![]).is_err());
        let a = layer(4, &[]);
        let b = layer(8, &[]);
        let err = LayeredMemory::new(vec![open(&a), open(&b)]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let empty = layer(0, &[]);
        let err = LayeredMemory::new(vec![open(&empty)]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn test_rejects_unaligned_extent() {
        // A layer whose size is not page aligned ends in a partial data
        // extent; overlaying it would hide the parent's bytes past EOF.
        let f = TempFile::new().unwrap();
        f.as_file().set_len(PAGE as u64 + 1).unwrap();
        f.as_file().write_all_at(&[1], PAGE as u64).unwrap();
        let err = LayeredMemory::new(vec![open(&f)]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_hole_only_root_reads_zero() {
        let root = layer(3, &[]);
        let mem = LayeredMemory::new(vec![open(&root)]).unwrap();
        assert_eq!(mem.extent_count, 0);
        assert!(mem.as_slice().iter().all(|&b| b == 0));
    }
}

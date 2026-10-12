// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Resolved ranges of guest memory, for the virtqueue rings.

use std::ops::Deref;
use std::sync::atomic::{AtomicU64, Ordering};

use vm_memory::{GuestMemoryBackend, GuestMemoryError};

use crate::arch::host_page_size;
use crate::vstate::memory::{ByteValued, GuestAddress, GuestMemoryMmap, mark_dirty_host};

/// A resolved guest-memory range with volatile accesses bounded by its original length.
///
/// Reusing the resolved pointer avoids a region lookup on each access.
///
/// The slice does not keep its mapping alive. Devices retain it in `ActiveState::mem` until
/// reset. Ballooning and virtio-mem preserve the virtual address range when reclaiming pages.
///
/// A slice is read-only; [`GuestMemorySliceMut`] is for ranges Firecracker writes to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GuestMemorySlice {
    base: *mut u8,
    len: usize,
}

// SAFETY: `base` points into guest memory, which is shared by design and is only reached through
// the bounds-checked volatile accessors below. A slice owns nothing and holds no thread-affine
// state, so moving one to a device's worker thread is sound.
unsafe impl Send for GuestMemorySlice {}

impl GuestMemorySlice {
    /// An unresolved range used before queue initialization.
    pub(crate) const UNRESOLVED: Self = Self {
        base: std::ptr::null_mut(),
        len: 0,
    };

    /// Resolves `addr..addr + len`, which must lie within a single region.
    pub(crate) fn new<M: GuestMemoryBackend>(
        mem: &M,
        addr: GuestAddress,
        len: usize,
    ) -> Result<Self, GuestMemoryError> {
        let slice = mem.get_slice(addr, len)?;
        Ok(Self {
            base: slice.ptr_guard_mut().as_ptr(),
            len,
        })
    }

    #[inline(always)]
    fn ptr_at<T>(&self, offset: usize) -> Option<*mut T> {
        if offset
            .checked_add(std::mem::size_of::<T>())
            .is_none_or(|end| end > self.len)
        {
            return None;
        }
        // SAFETY: callers keep the mapping alive. The check above keeps
        // `[offset, offset + size_of::<T>())` within the range `new` validated.
        Some(unsafe { self.base.add(offset) }.cast())
    }

    /// Reads the `T` at `offset` bytes into the range, or `None` if it does not fit.
    ///
    /// # Safety
    ///
    /// In-bounds addresses must be aligned for `T` and valid for reads.
    #[inline(always)]
    pub(crate) unsafe fn read_obj<T: ByteValued>(&self, offset: usize) -> Option<T> {
        let ptr = self.ptr_at::<T>(offset)?;
        // SAFETY: `ptr_at` bounds the access. The caller guarantees alignment and a live mapping.
        Some(unsafe { ptr.read_volatile() })
    }

    /// Reads the final `T`, or `None` if the range is too short.
    ///
    /// # Safety
    ///
    /// The final `T`, if it fits, must be aligned and valid for reads.
    #[inline(always)]
    pub(crate) unsafe fn read_last<T: ByteValued>(&self) -> Option<T> {
        // SAFETY: the caller upholds `read_obj`'s requirements at the tail offset.
        unsafe { self.read_obj(self.last_offset::<T>()?) }
    }

    #[inline(always)]
    fn last_offset<T>(&self) -> Option<usize> {
        self.len.checked_sub(std::mem::size_of::<T>())
    }
}

/// A [`GuestMemorySlice`] Firecracker writes to (e.g. a virtqueue used ring).
///
/// Each write records the pages it touches in a bitmap of the range's pages, and
/// [`Self::mark_dirty`] reports them to the dirty bitmap when a snapshot is taken. The bitmap is
/// only ever written by the slice's owner, so recording never contends with other threads,
/// unlike an atomic update of the shared dirty bitmap would.
#[derive(Debug)]
pub(crate) struct GuestMemorySliceMut {
    slice: GuestMemorySlice,
    /// Offset of the range's start within its first page.
    first_page_offset: usize,
    /// `log2` of the page size.
    page_shift: u32,
    /// One bit per page of the range: whether it was written since the last `mark_dirty`.
    written: AtomicU64,
}

impl GuestMemorySliceMut {
    /// An unresolved range used before queue initialization.
    pub(crate) const fn unresolved() -> Self {
        Self {
            slice: GuestMemorySlice::UNRESOLVED,
            first_page_offset: 0,
            page_shift: 0,
            written: AtomicU64::new(0),
        }
    }

    /// Resolves `addr..addr + len`, which must lie within a single region.
    ///
    /// # Panics
    ///
    /// Panics if the range covers more than 64 pages.
    pub(crate) fn new<M: GuestMemoryBackend>(
        mem: &M,
        addr: GuestAddress,
        len: usize,
    ) -> Result<Self, GuestMemoryError> {
        let slice = GuestMemorySlice::new(mem, addr, len)?;
        // Regions are page-aligned in both guest and host memory, so host and guest pages
        // coincide and the host address tells which page a byte is on.
        let page_size = host_page_size();
        let first_page_offset = slice.base.addr() % page_size;
        assert!(
            (first_page_offset + len).div_ceil(page_size) <= 64,
            "range covers more than 64 pages"
        );
        Ok(Self {
            slice,
            first_page_offset,
            page_shift: page_size.trailing_zeros(),
            written: AtomicU64::new(0),
        })
    }

    /// Records that the `len` bytes at `offset` into the range were written.
    #[inline(always)]
    fn set_written(&self, offset: usize, len: usize) {
        let pages = create_dirty_bitmap(self.first_page_offset + offset, len, self.page_shift);
        self.written.fetch_or(pages, Ordering::Release);
    }

    /// Marks dirty in `mem` the pages written since the last call.
    pub(crate) fn mark_dirty(&self, mem: &GuestMemoryMmap) {
        let pages = self.written.swap(0, Ordering::Acquire);
        iterate_on_dirty_pages(pages, self.page_shift, |offset| {
            // `offset` is from the start of page 0, which we need to convert to a host address.
            // Note: `offset < self.first_page_offset` is possible for the first page.
            let host_addr = self
                .ptr_at::<u8>(offset.saturating_sub(self.first_page_offset))
                .expect("written page outside the range");
            mark_dirty_host(mem, host_addr, 1);
        });
    }

    /// Writes `val` at `offset` bytes into the range, or returns `None` if it does not fit.
    ///
    /// # Safety
    ///
    /// In-bounds addresses must be aligned for `T` and valid for writes.
    #[inline(always)]
    #[must_use]
    pub(crate) unsafe fn write_obj<T: ByteValued>(&mut self, val: T, offset: usize) -> Option<()> {
        let ptr = self.ptr_at::<T>(offset)?;
        // SAFETY: `ptr_at` bounds the access. The caller guarantees alignment and a live mapping.
        unsafe { ptr.write_volatile(val) };
        self.set_written(offset, std::mem::size_of::<T>());
        Some(())
    }

    /// Writes `val` into the final `T`-sized slot, or returns `None` if it does not fit.
    ///
    /// # Safety
    ///
    /// The final `T`, if it fits, must be aligned and valid for writes.
    #[inline(always)]
    #[must_use]
    pub(crate) unsafe fn write_last<T: ByteValued>(&mut self, val: T) -> Option<()> {
        // SAFETY: the caller upholds `write_obj`'s requirements at the tail offset.
        unsafe { self.write_obj(val, self.last_offset::<T>()?) }
    }
}

/// The read side of a mutable slice is the plain slice.
impl Deref for GuestMemorySliceMut {
    type Target = GuestMemorySlice;

    fn deref(&self) -> &GuestMemorySlice {
        &self.slice
    }
}

/// Creates a dirty bitmap representing 64 pages of guest memory, where `len` bytes starting at
/// `offset` changed.
#[inline(always)]
fn create_dirty_bitmap(offset: usize, len: usize, page_shift: u32) -> u64 {
    // The write covers the pages from the one holding its first byte to the one holding its
    // last byte.
    let first = offset >> page_shift;
    let last = (offset + len - 1) >> page_shift;
    // Bits `first..=last`: all the bits from `first` up, intersected with all the bits up to
    // `last`.
    (u64::MAX << first) & (u64::MAX >> (63 - last))
}

/// Calls `f` with the offset of the first byte of each page set in `bitmap`, lowest page first.
#[inline(always)]
fn iterate_on_dirty_pages(mut bitmap: u64, page_shift: u32, mut f: impl FnMut(usize)) {
    while bitmap != 0 {
        // The lowest set bit has that many zero bits below it.
        let page = bitmap.trailing_zeros() as usize;
        // Subtracting 1 flips the lowest set bit and the zeros below it; the AND then keeps all
        // the other bits, clearing exactly the one just read.
        bitmap &= bitmap - 1;
        f(page << page_shift);
    }
}

#[cfg(kani)]
mod verification {
    use super::{create_dirty_bitmap, iterate_on_dirty_pages};

    const PAGE_SHIFT: u32 = 12;
    const PAGE: usize = 1 << PAGE_SHIFT;
    // Three pages let a write start and end on any page but the first.
    const NR_PAGES: usize = 3;

    /// `create_dirty_bitmap` sets the bit of every page the write touches, and of no other
    /// page: every written byte is on a set page, and every set page holds a written byte.
    #[kani::proof]
    #[kani::unwind(5)]
    fn verify_create_dirty_bitmap() {
        let offset: usize = kani::any_where(|&o| o < NR_PAGES * PAGE);
        let len: usize = kani::any_where(|&l| l >= 1 && l <= NR_PAGES * PAGE - offset);

        let bitmap = create_dirty_bitmap(offset, len, PAGE_SHIFT);

        // Check one arbitrary written byte; Kani covers all of them.
        let byte: usize = kani::any_where(|&b| b >= offset && b < offset + len);
        assert!(bitmap & (1 << (byte >> PAGE_SHIFT)) != 0);

        // Every set page holds a written byte: the later of its first byte and the write's.
        iterate_on_dirty_pages(bitmap, PAGE_SHIFT, |page_start| {
            let byte = page_start.max(offset);
            assert!(byte < page_start + PAGE);
            assert!(byte < offset + len);
        });
    }

    /// The pages recorded for a write within the range are reported through offsets within the
    /// range, so `mark_dirty` never hits either of its panics: only page 0 starts before the
    /// range, and the first byte of every reported page that lies within the range is on a page
    /// the write touched.
    #[kani::proof]
    #[kani::unwind(5)]
    fn verify_reported_pages_within_range() {
        let first_page_offset: usize = kani::any_where(|&o| o < PAGE);
        let range_len: usize =
            kani::any_where(|&l| l >= 1 && l <= NR_PAGES * PAGE - first_page_offset);
        let offset: usize = kani::any_where(|&o| o < range_len);
        let len: usize = kani::any_where(|&l| l >= 1 && l <= range_len - offset);

        let bitmap = create_dirty_bitmap(first_page_offset + offset, len, PAGE_SHIFT);

        iterate_on_dirty_pages(bitmap, PAGE_SHIFT, |page_start| {
            assert!(page_start == 0 || page_start >= first_page_offset);
            let in_range = page_start.saturating_sub(first_page_offset);
            assert!(in_range < range_len);
            // The page overlaps the write.
            assert!(page_start < first_page_offset + offset + len);
            assert!(page_start + PAGE > first_page_offset + offset);
        });
    }

    /// `iterate_on_dirty_pages` visits every set page exactly once, lowest first, and no other,
    /// each through the offset of its first byte.
    #[kani::proof]
    #[kani::unwind(5)]
    fn verify_iterate_on_dirty_pages() {
        let bitmap: u64 = kani::any_where(|&b| b >> NR_PAGES == 0);

        let mut visited = 0u64;
        let mut last = None;
        iterate_on_dirty_pages(bitmap, PAGE_SHIFT, |offset| {
            assert_eq!(offset % PAGE, 0);
            let page = offset >> PAGE_SHIFT;
            assert!(last.is_none_or(|last| last < page));
            last = Some(page);
            visited |= 1 << page;
        });

        assert_eq!(visited, bitmap);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::multi_region_mem;
    use crate::vmm_config::machine_config::HugePageConfig;
    use crate::vstate::memory::test_utils::into_region_ext;
    use crate::vstate::memory::{Bitmap, Bytes, GuestMemoryExtension, anonymous};

    #[test]
    fn test_guest_memory_slice() {
        let mem = multi_region_mem(&[(GuestAddress(0), 0x1000), (GuestAddress(0x1000), 0x1000)]);

        GuestMemorySlice::new(&mem, GuestAddress(0xff8), 0x10).unwrap_err();
        GuestMemorySlice::new(&mem, GuestAddress(0x3000), 0x10).unwrap_err();

        let mut cache = GuestMemorySliceMut::new(&mem, GuestAddress(0x100), 0x10).unwrap();
        // SAFETY: `mem` outlives the caches. All in-bounds accesses are aligned; the remaining
        // accesses return `None` without dereferencing a pointer.
        unsafe {
            cache.write_obj::<u32>(0xdead_beef, 0).unwrap();
            assert_eq!(cache.read_obj::<u32>(0).unwrap(), 0xdead_beef);
            assert_eq!(
                mem.read_obj::<u32>(GuestAddress(0x100)).unwrap(),
                0xdead_beef
            );
            assert_eq!(cache.read_obj::<u16>(2).unwrap(), 0xdead);
            mem.write_obj::<u32>(0xcafe_f00d, GuestAddress(0x104))
                .unwrap();
            assert_eq!(cache.read_obj::<u32>(4).unwrap(), 0xcafe_f00d);

            cache.read_obj::<u32>(0xc).unwrap();
            assert_eq!(cache.read_obj::<u32>(0xd), None);
            assert_eq!(cache.read_obj::<u8>(0x10), None);
            assert_eq!(cache.read_obj::<u8>(usize::MAX), None);
            assert_eq!(cache.write_obj::<u8>(0, 0x10), None);

            cache.write_last::<u16>(0xbeef).unwrap();
            assert_eq!(cache.read_last::<u16>().unwrap(), 0xbeef);
            assert_eq!(mem.read_obj::<u16>(GuestAddress(0x10e)).unwrap(), 0xbeef);
            let mut short = GuestMemorySliceMut::new(&mem, GuestAddress(0x200), 1).unwrap();
            assert_eq!(short.read_last::<u16>(), None);
            assert_eq!(short.write_last::<u16>(0), None);

            // A read-only slice over the same range sees the writes.
            let ro = GuestMemorySlice::new(&mem, GuestAddress(0x100), 0x10).unwrap();
            assert_eq!(ro.read_obj::<u32>(0).unwrap(), 0xdead_beef);
            assert_eq!(ro.read_last::<u16>().unwrap(), 0xbeef);
            assert_eq!(ro.read_obj::<u8>(0x10), None);

            let mut unresolved = GuestMemorySliceMut::unresolved();
            assert_eq!(unresolved.read_obj::<u8>(0), None);
            assert_eq!(unresolved.write_obj::<u8>(0, 0), None);
            assert_eq!(unresolved.read_last::<u8>(), None);
            assert_eq!(unresolved.write_last::<u8>(0), None);
        }
    }

    #[test]
    fn test_guest_memory_slice_mut_dirty_tracking() {
        let page_size = host_page_size();
        let mem = into_region_ext(
            anonymous(
                &[(GuestAddress(0), page_size * 3)],
                true,
                HugePageConfig::None,
            )
            .unwrap(),
        );
        let dirty_at = |addr: usize| {
            mem.get_slices(GuestAddress(addr as u64), 1)
                .flatten()
                .all(|slice| slice.bitmap().dirty_at(0))
        };
        let clean = || !(0..3).any(|p| dirty_at(p * page_size));

        // A slice spanning the end of page 1 and the start of page 2.
        mem.reset_dirty();
        let mut slice =
            GuestMemorySliceMut::new(&mem, GuestAddress((2 * page_size - 8) as u64), 16).unwrap();

        // Resolving a slice marks nothing, and neither do reads.
        // SAFETY: `mem` outlives the slice; all accesses are aligned and in bounds.
        unsafe {
            slice.read_obj::<u32>(0).unwrap();
            slice.read_last::<u16>().unwrap();
            slice.mark_dirty(&mem);
            assert!(clean());

            // A write is reported by the next `mark_dirty`, for the page it landed on only.
            slice.write_obj::<u32>(1, 0).unwrap();
            assert!(clean());
            slice.mark_dirty(&mem);
            assert!(!dirty_at(0));
            assert!(dirty_at(page_size));
            assert!(!dirty_at(2 * page_size));

            // `mark_dirty` reports each write once.
            mem.reset_dirty();
            slice.mark_dirty(&mem);
            assert!(clean());

            slice.write_last::<u16>(2).unwrap();
            slice.mark_dirty(&mem);
            assert!(!dirty_at(page_size));
            assert!(dirty_at(2 * page_size));

            // A write straddling the two pages is reported for both.
            mem.reset_dirty();
            slice.write_obj::<[u32; 2]>([3, 3], 4).unwrap();
            slice.mark_dirty(&mem);
            assert!(dirty_at(page_size));
            assert!(dirty_at(2 * page_size));

            // An out-of-bounds write marks nothing.
            mem.reset_dirty();
            assert_eq!(slice.write_obj::<u32>(4, 16), None);
            slice.mark_dirty(&mem);
            assert!(clean());

            // With dirty page tracking off, the regions have no bitmap: writes still land and
            // `mark_dirty` has nothing to mark, without panicking.
            let untracked = into_region_ext(
                anonymous(&[(GuestAddress(0), page_size)], false, HugePageConfig::None).unwrap(),
            );
            let mut slice = GuestMemorySliceMut::new(&untracked, GuestAddress(0), 16).unwrap();
            slice.write_obj::<u32>(5, 0).unwrap();
            assert_eq!(slice.read_obj::<u32>(0).unwrap(), 5);
            slice.mark_dirty(&untracked);

            // An unresolved slice never writes and has nothing to report.
            let mut unresolved = GuestMemorySliceMut::unresolved();
            assert_eq!(unresolved.write_obj::<u8>(0, 0), None);
            unresolved.mark_dirty(&mem);
            assert!(clean());
        }
    }
}

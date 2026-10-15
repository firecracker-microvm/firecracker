// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Resolved ranges of guest memory, for the virtqueue rings.

use std::ops::Deref;
use std::sync::atomic::{AtomicU64, Ordering};

use vm_memory::bitmap::Bitmap;
use vm_memory::{GuestMemoryBackend, GuestMemoryError, GuestMemoryRegion};

use crate::arch::host_page_size;
use crate::utils::{u64_to_usize, usize_to_u64};
use crate::vstate::memory::{ByteValued, GuestAddress, GuestMemoryMmap};

/// Guest memory that may track its dirty pages.
pub trait DirtyTracking {
    /// The memory to report writes to, or `None` when dirty page tracking is off.
    fn dirty_tracking(&self) -> Option<GuestMemoryMmap>;
}

impl DirtyTracking for GuestMemoryMmap {
    fn dirty_tracking(&self) -> Option<GuestMemoryMmap> {
        self.iter()
            .any(|region| region.bitmap().is_some())
            .then(|| self.clone())
    }
}

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
/// With dirty page tracking on, each write records the pages it dirtied, and
/// [`Self::commit_dirty`] reports them to the guest memory's dirty bitmap when a snapshot is
/// taken. The record is only ever updated by the slice's owner, so recording never contends with
/// other threads, unlike an atomic update of the shared dirty bitmap would. With tracking off,
/// writes are plain writes.
///
/// A tracked slice must not be dropped with dirty pages it has not committed, since nothing else
/// knows about them: whoever lets go of a dirtied slice has to call `commit_dirty` first.
#[derive(Debug)]
pub(crate) enum GuestMemorySliceMut {
    /// Dirty page tracking is off.
    Untracked(GuestMemorySlice),
    /// Dirty page tracking is on.
    Tracked {
        slice: GuestMemorySlice,
        /// The pages dirtied since the last commit.
        dirty: DirtyPages,
        /// The guest memory to report the writes to.
        mem: GuestMemoryMmap,
        /// The address of the page holding the start of the range.
        first_page: GuestAddress,
    },
}

/// The pages of a range dirtied since they were last taken, one bit per page.
///
/// Pages are counted from the page holding the start of the range, which begins
/// `first_page_offset` bytes before the range.
#[derive(Debug)]
pub(crate) struct DirtyPages {
    /// Offset of the range's start within its first page.
    first_page_offset: usize,
    /// `log2` of the page size.
    page_shift: u32,
    /// One bit per page the range touches, counted from the page holding its start: whether the
    /// page was dirtied since the pages were last taken.
    dirty: AtomicU64,
}

impl DirtyPages {
    /// For a range of `range_len` bytes starting `first_page_offset` bytes into a page.
    ///
    /// # Panics
    ///
    /// Panics if the range covers more than 64 pages.
    fn new(first_page_offset: usize, range_len: usize, page_shift: u32) -> Self {
        // 64 bits for the pages from the one holding the start of the range to the one holding
        // its end.
        assert!(
            (first_page_offset + range_len).div_ceil(1 << page_shift) <= 64,
            "range covers more than 64 pages"
        );
        Self {
            first_page_offset,
            page_shift,
            dirty: AtomicU64::new(0),
        }
    }

    /// Records as dirty the pages holding the `len` bytes at `offset` into the range.
    #[inline(always)]
    fn record(&self, offset: usize, len: usize) {
        // The write covers the pages from the one holding its first byte to the one holding its
        // last byte, counted from the page holding the start of the range.
        let first = (offset + self.first_page_offset) >> self.page_shift;
        let last = (offset + self.first_page_offset + len - 1) >> self.page_shift;
        // Bits `first..=last`: all the bits from `first` up, intersected with all the bits up to
        // `last`.
        let pages = (u64::MAX << first) & (u64::MAX >> (63 - last));
        self.dirty.fetch_or(pages, Ordering::Release);
    }

    /// Whether no page was dirtied since the pages were last taken.
    fn is_empty(&self) -> bool {
        self.dirty.load(Ordering::Acquire) == 0
    }

    /// Takes the pages dirtied since the last call, handing `f` each one's start as an offset from
    /// the start of the range's first page, lowest page first.
    fn take(&self, mut f: impl FnMut(usize)) {
        let mut pages = self.dirty.swap(0, Ordering::Acquire);
        while pages != 0 {
            // The lowest set bit has that many zero bits below it.
            let page = pages.trailing_zeros() as usize;
            // Subtracting 1 flips the lowest set bit and the zeros below it; the AND then keeps
            // all the other bits, clearing exactly the one just read.
            pages &= pages - 1;
            f(page << self.page_shift);
        }
    }
}

impl GuestMemorySliceMut {
    /// An unresolved range used before queue initialization.
    pub(crate) const UNRESOLVED: Self = Self::Untracked(GuestMemorySlice::UNRESOLVED);

    /// Resolves `addr..addr + len`, which must lie within a single region.
    ///
    /// # Panics
    ///
    /// Panics if dirty page tracking is on and the range covers more than 64 pages.
    pub(crate) fn new<M: GuestMemoryBackend + DirtyTracking>(
        mem: &M,
        addr: GuestAddress,
        len: usize,
    ) -> Result<Self, GuestMemoryError> {
        let slice = GuestMemorySlice::new(mem, addr, len)?;
        let Some(tracking_mem) = mem.dirty_tracking() else {
            return Ok(Self::Untracked(slice));
        };
        // Regions are page-aligned in both guest and host memory, so host and guest pages
        // coincide: the bitmap tracks guest pages of the host page size.
        let page_size = host_page_size();
        let first_page_offset = u64_to_usize(addr.0) % page_size;
        Ok(Self::Tracked {
            slice,
            dirty: DirtyPages::new(first_page_offset, len, page_size.trailing_zeros()),
            mem: tracking_mem,
            first_page: GuestAddress(addr.0 - usize_to_u64(first_page_offset)),
        })
    }

    /// Marks in the guest memory's bitmap the pages dirtied since the last call.
    pub(crate) fn commit_dirty(&self) {
        let Self::Tracked {
            dirty,
            mem,
            first_page,
            ..
        } = self
        else {
            return;
        };
        let (region, first_page_start) = mem
            .to_region_addr(*first_page)
            .expect("range resolved in this memory");
        let first_page_start = u64_to_usize(first_page_start.0);
        // Marking one byte marks the whole page.
        dirty.take(|page_start| region.bitmap().mark_dirty(first_page_start + page_start, 1));
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
        if let Self::Tracked { dirty, .. } = self {
            dirty.record(offset, std::mem::size_of::<T>());
        }
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

impl Drop for GuestMemorySliceMut {
    fn drop(&mut self) {
        // A panic while already panicking aborts the process, hiding the original panic.
        if let Self::Tracked { dirty, .. } = self
            && !std::thread::panicking()
        {
            assert!(
                dirty.is_empty(),
                "guest memory slice dropped with uncommitted dirty pages"
            );
        }
    }
}

/// The read side of a mutable slice is the plain slice.
impl Deref for GuestMemorySliceMut {
    type Target = GuestMemorySlice;

    fn deref(&self) -> &GuestMemorySlice {
        match self {
            Self::Untracked(slice) | Self::Tracked { slice, .. } => slice,
        }
    }
}

#[cfg(kani)]
mod verification {
    use super::DirtyPages;

    const PAGE_SHIFT: u32 = 12;
    const PAGE: usize = 1 << PAGE_SHIFT;
    // Three pages are enough for a write to relate to a page in every way: not touch it, start
    // in it, end in it, or cover it entirely (the middle page). More pages only repeat these.
    const NR_PAGES: usize = 3;

    /// Taking the pages recorded for a write hands over every page the write touches and no
    /// other, each once, lowest first, and leaves no page recorded.
    #[kani::proof]
    #[kani::unwind(5)]
    fn verify_dirty_pages() {
        let first_page_offset: usize = kani::any_where(|&o| o < PAGE);
        let range_len: usize =
            kani::any_where(|&l| l >= 1 && l <= NR_PAGES * PAGE - first_page_offset);
        let offset: usize = kani::any_where(|&o| o < range_len);
        let len: usize = kani::any_where(|&l| l >= 1 && l <= range_len - offset);

        let pages = DirtyPages::new(first_page_offset, range_len, PAGE_SHIFT);
        assert!(pages.is_empty());
        pages.record(offset, len);
        assert!(!pages.is_empty());

        // The write and one arbitrary byte of it, as offsets from the first page's start like the
        // pages handed over. Kani covers all the bytes.
        let write_start = first_page_offset + offset;
        let write_end = write_start + len;
        let byte: usize = kani::any_where(|&b| b >= write_start && b < write_end);
        let mut byte_handed_over = false;
        let mut last_end = 0;
        pages.take(|page_start| {
            assert_eq!(page_start % PAGE, 0);
            let page_end = page_start + PAGE;
            // Overlapping the write: starting before it ends, and ending after it starts.
            assert!(page_start < write_end);
            assert!(page_end > write_start);
            // After the previous page.
            assert!(page_start >= last_end);
            last_end = page_end;
            byte_handed_over |= page_start <= byte && byte < page_end;
        });
        assert!(byte_handed_over);

        assert!(pages.is_empty());
        pages.take(|_| unreachable!("page taken twice"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{
        multi_region_mem, single_region_mem, single_region_mem_dirty_tracking,
    };
    use crate::vstate::memory::{Bitmap, Bytes, GuestMemoryExtension};

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

            let mut unresolved = GuestMemorySliceMut::UNRESOLVED;
            assert_eq!(unresolved.read_obj::<u8>(0), None);
            assert_eq!(unresolved.write_obj::<u8>(0, 0), None);
            assert_eq!(unresolved.read_last::<u8>(), None);
            assert_eq!(unresolved.write_last::<u8>(0), None);
        }
    }

    #[test]
    fn test_guest_memory_slice_mut_dirty_tracking() {
        let page_size = host_page_size();
        let mem = single_region_mem_dirty_tracking(page_size * 3);
        let dirty_at = |addr: usize| {
            mem.find_region(GuestAddress(0))
                .unwrap()
                .bitmap()
                .dirty_at(addr)
        };
        let clean = || !(0..3).any(|p| dirty_at(p * page_size));

        // A slice spanning the end of page 1 and the start of page 2.
        mem.reset_dirty();
        let mut slice =
            GuestMemorySliceMut::new(&mem, GuestAddress(usize_to_u64(2 * page_size - 8)), 16)
                .unwrap();

        // Resolving a slice marks nothing, and neither do reads.
        // SAFETY: `mem` outlives the slice; all accesses are aligned and in bounds.
        unsafe {
            slice.read_obj::<u32>(0).unwrap();
            slice.read_last::<u16>().unwrap();
            slice.commit_dirty();
            assert!(clean());

            // A write is reported by the next `commit_dirty`, for the page it landed on only.
            slice.write_obj::<u32>(1, 0).unwrap();
            assert!(clean());
            slice.commit_dirty();
            assert!(!dirty_at(0));
            assert!(dirty_at(page_size));
            assert!(!dirty_at(2 * page_size));

            // `commit_dirty` reports each write once.
            mem.reset_dirty();
            slice.commit_dirty();
            assert!(clean());

            slice.write_last::<u16>(2).unwrap();
            slice.commit_dirty();
            assert!(!dirty_at(page_size));
            assert!(dirty_at(2 * page_size));

            // A write straddling the two pages is reported for both.
            mem.reset_dirty();
            slice.write_obj::<[u32; 2]>([3, 3], 4).unwrap();
            slice.commit_dirty();
            assert!(dirty_at(page_size));
            assert!(dirty_at(2 * page_size));

            // An out-of-bounds write marks nothing.
            mem.reset_dirty();
            assert_eq!(slice.write_obj::<u32>(4, 16), None);
            slice.commit_dirty();
            assert!(clean());

            // With dirty page tracking off, the regions have no bitmap: writes still land and
            // `commit_dirty` has nothing to mark, without panicking.
            let untracked = single_region_mem(page_size);
            let mut slice = GuestMemorySliceMut::new(&untracked, GuestAddress(0), 16).unwrap();
            slice.write_obj::<u32>(5, 0).unwrap();
            assert_eq!(slice.read_obj::<u32>(0).unwrap(), 5);
            slice.commit_dirty();

            // An unresolved slice never writes and has nothing to report.
            let mut unresolved = GuestMemorySliceMut::UNRESOLVED;
            assert_eq!(unresolved.write_obj::<u8>(0, 0), None);
            unresolved.commit_dirty();
            assert!(clean());
        }
    }
}

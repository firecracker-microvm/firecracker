// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Resolved ranges of guest memory, for the virtqueue rings.

use std::ops::Deref;

use vm_memory::bitmap::Bitmap;
use vm_memory::{GuestMemoryBackend, GuestMemoryError};

use crate::vstate::memory::{ByteValued, GuestAddress};

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

    /// Resolves `addr..addr + len`, which must lie within a single region, and marks it dirty.
    pub(crate) fn new<M: GuestMemoryBackend>(
        mem: &M,
        addr: GuestAddress,
        len: usize,
    ) -> Result<Self, GuestMemoryError> {
        let slice = mem.get_slice(addr, len)?;
        slice.bitmap().mark_dirty(0, len);
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
#[derive(Debug)]
pub(crate) struct GuestMemorySliceMut {
    slice: GuestMemorySlice,
}

impl GuestMemorySliceMut {
    /// An unresolved range used before queue initialization.
    pub(crate) const UNRESOLVED: Self = Self {
        slice: GuestMemorySlice::UNRESOLVED,
    };

    /// Resolves `addr..addr + len`, which must lie within a single region, and marks it dirty.
    pub(crate) fn new<M: GuestMemoryBackend>(
        mem: &M,
        addr: GuestAddress,
        len: usize,
    ) -> Result<Self, GuestMemoryError> {
        Ok(Self {
            slice: GuestMemorySlice::new(mem, addr, len)?,
        })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::host_page_size;
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

            let mut unresolved = GuestMemorySliceMut::UNRESOLVED;
            assert_eq!(unresolved.read_obj::<u8>(0), None);
            assert_eq!(unresolved.write_obj::<u8>(0, 0), None);
            assert_eq!(unresolved.read_last::<u8>(), None);
            assert_eq!(unresolved.write_last::<u8>(0), None);
        }
    }

    #[test]
    fn test_guest_memory_slice_marks_range_dirty() {
        let page_size = host_page_size();
        let mem = into_region_ext(
            anonymous(
                &[(GuestAddress(0), page_size * 3)],
                true,
                HugePageConfig::None,
            )
            .unwrap(),
        );

        mem.reset_dirty();
        GuestMemorySlice::new(&mem, GuestAddress(page_size as u64), page_size).unwrap();

        let dirty_at = |addr: usize| {
            mem.get_slices(GuestAddress(addr as u64), 1)
                .flatten()
                .all(|slice| slice.bitmap().dirty_at(0))
        };
        assert!(!dirty_at(0));
        assert!(dirty_at(page_size));
        assert!(!dirty_at(page_size * 2));
    }
}

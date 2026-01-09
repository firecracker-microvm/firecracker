// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::fs::File;
use std::io::SeekFrom;
use std::ops::Deref;
use std::sync::{Arc, Mutex};

use bitvec::vec::BitVec;
use kvm_bindings::{KVM_MEM_LOG_DIRTY_PAGES, kvm_userspace_memory_region};
use log::error;
use serde::{Deserialize, Serialize};
pub use vm_memory::bitmap::{AtomicBitmap, BS, Bitmap, BitmapSlice};
pub use vm_memory::mmap::MmapRegionBuilder;
use vm_memory::mmap::{MmapRegionError, NewBitmap};
pub use vm_memory::{
    Address, ByteValued, Bytes, FileOffset, GuestAddress, GuestMemory, GuestMemoryRegion,
    GuestUsize, MemoryRegionAddress, MmapRegion, address,
};
use vm_memory::{GuestMemoryError, GuestMemoryRegionBytes, VolatileSlice, WriteVolatile};
use vmm_sys_util::errno;

use crate::utils::{get_page_size, u64_to_usize};
use crate::vmm_config::machine_config::HugePageConfig;
use crate::vstate::vm::VmError;
use crate::{DirtyBitmap, Vm};

/// Type of GuestRegionMmap.
pub type GuestRegionMmap = vm_memory::GuestRegionMmap<Option<AtomicBitmap>>;
/// Type of GuestMemoryMmap.
pub type GuestMemoryMmap = vm_memory::GuestRegionCollection<GuestRegionMmapExt>;
/// Type of GuestMmapRegion.
pub type GuestMmapRegion = vm_memory::MmapRegion<Option<AtomicBitmap>>;

/// Errors associated with dumping guest memory to file.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum MemoryError {
    /// Cannot fetch system's page size: {0}
    PageSize(errno::Error),
    /// Cannot dump memory: {0}
    WriteMemory(GuestMemoryError),
    /// Cannot create mmap region: {0}
    MmapRegionError(MmapRegionError),
    /// Cannot create guest memory
    VmMemoryError,
    /// Cannot create memfd: {0}
    Memfd(memfd::Error),
    /// Cannot resize memfd file: {0}
    MemfdSetLen(std::io::Error),
    /// Total sum of memory regions exceeds largest possible file offset
    OffsetTooLarge,
    /// Cannot retrieve snapshot file metadata: {0}
    FileMetadata(std::io::Error),
    /// Memory region is not aligned
    Unaligned,
    /// Error protecting memory slot: {0}
    Mprotect(std::io::Error),
}

/// Type of the guest region
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum GuestRegionType {
    /// Guest DRAM
    Dram,
    /// Hotpluggable memory
    Hotpluggable,
}

/// An extension to GuestMemoryRegion that can be split into multiple KVM slots of
/// the same slot_size, and stores the type of region, and the starting KVM slot number.
#[derive(Debug)]
pub struct GuestRegionMmapExt {
    /// the wrapped GuestRegionMmap
    pub inner: GuestRegionMmap,
    /// the type of region
    pub region_type: GuestRegionType,
    /// the starting KVM slot number assigned to this region
    pub slot_from: u32,
    /// the size of the slots of this region
    pub slot_size: usize,
    /// a bitvec indicating whether slot `i` is plugged into KVM (1) or not (0)
    pub plugged: Mutex<BitVec>,
}

/// A guest memory slot, which is a slice of a guest memory region
#[derive(Debug)]
pub struct GuestMemorySlot<'a> {
    /// KVM memory slot number
    pub(crate) slot: u32,
    /// Start guest address of the slot
    pub(crate) guest_addr: GuestAddress,
    /// Corresponding slice in host memory
    pub(crate) slice: VolatileSlice<'a, BS<'a, Option<AtomicBitmap>>>,
}

impl From<&GuestMemorySlot<'_>> for kvm_userspace_memory_region {
    fn from(mem_slot: &GuestMemorySlot) -> Self {
        let flags = if mem_slot.slice.bitmap().is_some() {
            KVM_MEM_LOG_DIRTY_PAGES
        } else {
            0
        };
        kvm_userspace_memory_region {
            flags,
            slot: mem_slot.slot,
            guest_phys_addr: mem_slot.guest_addr.raw_value(),
            memory_size: mem_slot.slice.len() as u64,
            userspace_addr: mem_slot.slice.ptr_guard().as_ptr() as u64,
        }
    }
}

impl<'a> GuestMemorySlot<'a> {
    /// Dumps the dirty pages in this slot onto the writer
    pub(crate) fn dump_dirty<T: WriteVolatile + std::io::Seek>(
        &self,
        writer: &mut T,
        kvm_bitmap: &[u64],
        page_size: usize,
    ) -> Result<(), GuestMemoryError> {
        let firecracker_bitmap = self.slice.bitmap();
        let mut write_size = 0;
        let mut skip_size = 0;
        let mut dirty_batch_start = 0;

        for (i, v) in kvm_bitmap.iter().enumerate() {
            for j in 0..64 {
                let is_kvm_page_dirty = ((v >> j) & 1u64) != 0u64;
                let page_offset = ((i * 64) + j) * page_size;
                let is_firecracker_page_dirty = firecracker_bitmap.dirty_at(page_offset);

                if is_kvm_page_dirty || is_firecracker_page_dirty {
                    // We are at the start of a new batch of dirty pages.
                    if skip_size > 0 {
                        // Seek forward over the unmodified pages.
                        writer
                            .seek(SeekFrom::Current(skip_size.try_into().unwrap()))
                            .unwrap();
                        dirty_batch_start = page_offset;
                        skip_size = 0;
                    }
                    write_size += page_size;
                } else {
                    // We are at the end of a batch of dirty pages.
                    if write_size > 0 {
                        // Dump the dirty pages.
                        let slice = &self.slice.subslice(dirty_batch_start, write_size)?;
                        writer.write_all_volatile(slice)?;
                        write_size = 0;
                    }
                    skip_size += page_size;
                }
            }
        }

        if write_size > 0 {
            writer.write_all_volatile(&self.slice.subslice(dirty_batch_start, write_size)?)?;
        }

        Ok(())
    }

    /// Makes the slot host memory PROT_NONE (true) or PROT_READ|PROT_WRITE (false)
    pub(crate) fn protect(&self, protected: bool) -> Result<(), MemoryError> {
        let prot = if protected {
            libc::PROT_NONE
        } else {
            libc::PROT_READ | libc::PROT_WRITE
        };
        // SAFETY: Parameters refer to an existing host memory region
        let ret = unsafe {
            libc::mprotect(
                self.slice.ptr_guard_mut().as_ptr().cast(),
                self.slice.len(),
                prot,
            )
        };
        if ret != 0 {
            Err(MemoryError::Mprotect(std::io::Error::last_os_error()))
        } else {
            Ok(())
        }
    }
}

fn addr_in_range(addr: GuestAddress, start: GuestAddress, len: usize) -> bool {
    if let Some(end) = start.checked_add(len as u64) {
        addr >= start && addr < end
    } else {
        false
    }
}

impl GuestRegionMmapExt {
    /// Adds a DRAM region which only contains a single plugged slot
    pub(crate) fn dram_from_mmap_region(region: GuestRegionMmap, slot: u32) -> Self {
        let slot_size = u64_to_usize(region.len());
        GuestRegionMmapExt {
            inner: region,
            region_type: GuestRegionType::Dram,
            slot_from: slot,
            slot_size,
            plugged: Mutex::new(BitVec::repeat(true, 1)),
        }
    }

    /// Adds an hotpluggable region which can contain multiple slots and is initially unplugged
    pub(crate) fn hotpluggable_from_mmap_region(
        region: GuestRegionMmap,
        slot_from: u32,
        slot_size: usize,
    ) -> Self {
        let slot_cnt = (u64_to_usize(region.len())) / slot_size;

        GuestRegionMmapExt {
            inner: region,
            region_type: GuestRegionType::Hotpluggable,
            slot_from,
            slot_size,
            plugged: Mutex::new(BitVec::repeat(false, slot_cnt)),
        }
    }

    pub(crate) fn from_state(
        region: GuestRegionMmap,
        state: &GuestMemoryRegionState,
        slot_from: u32,
    ) -> Result<Self, MemoryError> {
        let slot_cnt = state.plugged.len();
        let slot_size = u64_to_usize(region.len())
            .checked_div(slot_cnt)
            .ok_or(MemoryError::Unaligned)?;

        Ok(GuestRegionMmapExt {
            inner: region,
            slot_size,
            region_type: state.region_type,
            slot_from,
            plugged: Mutex::new(BitVec::from_iter(state.plugged.iter())),
        })
    }

    pub(crate) fn slot_cnt(&self) -> u32 {
        u32::try_from(u64_to_usize(self.len()) / self.slot_size).unwrap()
    }

    pub(crate) fn mem_slot(&self, slot: u32) -> GuestMemorySlot<'_> {
        assert!(slot >= self.slot_from && slot < self.slot_from + self.slot_cnt());

        let offset = ((slot - self.slot_from) as u64) * (self.slot_size as u64);

        GuestMemorySlot {
            slot,
            guest_addr: self.start_addr().unchecked_add(offset),
            slice: self
                .inner
                .get_slice(MemoryRegionAddress(offset), self.slot_size)
                .expect("slot range should be valid"),
        }
    }

    /// Returns a snapshot of the slots and their state at the time of calling
    ///
    /// Note: to avoid TOCTOU races use only within VMM thread.
    pub(crate) fn slots(&self) -> impl Iterator<Item = (GuestMemorySlot<'_>, bool)> {
        self.plugged
            .lock()
            .unwrap()
            .iter()
            .enumerate()
            .map(|(i, b)| {
                (
                    self.mem_slot(self.slot_from + u32::try_from(i).unwrap()),
                    *b,
                )
            })
            .collect::<Vec<_>>()
            .into_iter()
    }

    /// Returns a snapshot of the plugged slots at the time of calling
    ///
    /// Note: to avoid TOCTOU races use only within VMM thread.
    pub(crate) fn plugged_slots(&self) -> impl Iterator<Item = GuestMemorySlot<'_>> {
        self.slots()
            .filter(|(_, plugged)| *plugged)
            .map(|(slot, _)| slot)
    }

    pub(crate) fn slots_intersecting_range(
        &self,
        from: GuestAddress,
        len: usize,
    ) -> impl Iterator<Item = GuestMemorySlot<'_>> {
        self.slots().map(|(slot, _)| slot).filter(move |slot| {
            if let Some(slot_end) = slot.guest_addr.checked_add(slot.slice.len() as u64) {
                addr_in_range(slot.guest_addr, from, len) || addr_in_range(slot_end, from, len)
            } else {
                false
            }
        })
    }

    /// (un)plug a slot from an Hotpluggable memory region
    pub(crate) fn update_slot(
        &self,
        vm: &Vm,
        mem_slot: &GuestMemorySlot<'_>,
        plug: bool,
    ) -> Result<(), VmError> {
        // This function can only be called on hotpluggable regions!
        assert!(self.region_type == GuestRegionType::Hotpluggable);

        let mut bitmap_guard = self.plugged.lock().unwrap();
        let prev = bitmap_guard.replace((mem_slot.slot - self.slot_from) as usize, plug);
        // do not do anything if the state is what we're trying to set
        if prev == plug {
            return Ok(());
        }

        let mut kvm_region = kvm_userspace_memory_region::from(mem_slot);
        if plug {
            // make it accessible _before_ adding it to KVM
            mem_slot.protect(false)?;
            vm.set_user_memory_region(kvm_region)?;
        } else {
            // to remove it we need to pass a size of zero
            kvm_region.memory_size = 0;
            vm.set_user_memory_region(kvm_region)?;
            // make it protected _after_ removing it from KVM
            mem_slot.protect(true)?;
        }
        Ok(())
    }

    pub(crate) fn discard_range(
        &self,
        caddr: MemoryRegionAddress,
        len: usize,
    ) -> Result<(), GuestMemoryError> {
        let phys_address = self.get_host_address(caddr)?;

        match (self.inner.file_offset(), self.inner.flags()) {
            // If and only if we are resuming from a snapshot file, we have a file and it's mapped
            // private
            (Some(_), flags) if flags & libc::MAP_PRIVATE != 0 => {
                // Mmap a new anonymous region over the present one in order to create a hole
                // with zero pages.
                // This workaround is (only) needed after resuming from a snapshot file because the
                // guest memory is mmaped from file as private. In this case, MADV_DONTNEED on the
                // file only drops any anonymous pages in range, but subsequent accesses would read
                // whatever page is stored on the backing file. Mmapping anonymous pages ensures
                // it's zeroed.
                // SAFETY: The address and length are known to be valid.
                let ret = unsafe {
                    libc::mmap(
                        phys_address.cast(),
                        len,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_FIXED | libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                        -1,
                        0,
                    )
                };
                if ret == libc::MAP_FAILED {
                    let os_error = std::io::Error::last_os_error();
                    error!("discard_range: mmap failed: {:?}", os_error);
                    Err(GuestMemoryError::IOError(os_error))
                } else {
                    Ok(())
                }
            }
            // Match either the case of an anonymous mapping, or the case
            // of a shared file mapping.
            // TODO: madvise(MADV_DONTNEED) doesn't actually work with memfd
            // (or in general MAP_SHARED of a fd). In those cases we should use
            // fallocate64(FALLOC_FL_PUNCH_HOLE|FALLOC_FL_KEEP_SIZE).
            // We keep falling to the madvise branch to keep the previous behaviour.
            _ => {
                // Madvise the region in order to mark it as not used.
                // SAFETY: The address and length are known to be valid.
                let ret = unsafe { libc::madvise(phys_address.cast(), len, libc::MADV_DONTNEED) };
                if ret < 0 {
                    let os_error = std::io::Error::last_os_error();
                    error!("discard_range: madvise failed: {:?}", os_error);
                    Err(GuestMemoryError::IOError(os_error))
                } else {
                    Ok(())
                }
            }
        }
    }
}

impl Deref for GuestRegionMmapExt {
    type Target = MmapRegion<Option<AtomicBitmap>>;

    fn deref(&self) -> &MmapRegion<Option<AtomicBitmap>> {
        &self.inner
    }
}

impl GuestMemoryRegionBytes for GuestRegionMmapExt {}

#[allow(clippy::cast_possible_wrap)]
#[allow(clippy::cast_possible_truncation)]
impl GuestMemoryRegion for GuestRegionMmapExt {
    type B = Option<AtomicBitmap>;

    fn len(&self) -> GuestUsize {
        self.inner.len()
    }

    fn start_addr(&self) -> GuestAddress {
        self.inner.start_addr()
    }

    fn bitmap(&self) -> BS<'_, Self::B> {
        self.inner.bitmap()
    }

    fn get_host_address(
        &self,
        addr: MemoryRegionAddress,
    ) -> vm_memory::guest_memory::Result<*mut u8> {
        self.inner.get_host_address(addr)
    }

    fn file_offset(&self) -> Option<&FileOffset> {
        self.inner.file_offset()
    }

    fn get_slice(
        &self,
        offset: MemoryRegionAddress,
        count: usize,
    ) -> vm_memory::guest_memory::Result<VolatileSlice<'_, BS<'_, Self::B>>> {
        self.inner.get_slice(offset, count)
    }
}

/// Creates a `Vec` of `GuestRegionMmap` with the given configuration
pub fn create(
    regions: impl Iterator<Item = (GuestAddress, usize)>,
    mmap_flags: libc::c_int,
    file: Option<File>,
    track_dirty_pages: bool,
) -> Result<Vec<GuestRegionMmap>, MemoryError> {
    let mut offset = 0;
    let file = file.map(Arc::new);
    regions
        .map(|(start, size)| {
            let mut builder = MmapRegionBuilder::new_with_bitmap(
                size,
                track_dirty_pages.then(|| AtomicBitmap::with_len(size)),
            )
            .with_mmap_prot(libc::PROT_READ | libc::PROT_WRITE)
            .with_mmap_flags(libc::MAP_NORESERVE | mmap_flags);

            if let Some(ref file) = file {
                let file_offset = FileOffset::from_arc(Arc::clone(file), offset);

                builder = builder.with_file_offset(file_offset);
            }

            offset = match offset.checked_add(size as u64) {
                None => return Err(MemoryError::OffsetTooLarge),
                Some(new_off) if new_off >= i64::MAX as u64 => {
                    return Err(MemoryError::OffsetTooLarge);
                }
                Some(new_off) => new_off,
            };

            GuestRegionMmap::new(
                builder.build().map_err(MemoryError::MmapRegionError)?,
                start,
            )
            .ok_or(MemoryError::VmMemoryError)
        })
        .collect::<Result<Vec<_>, _>>()
}

/// Creates a GuestMemoryMmap with `size` in MiB backed by a memfd.
pub fn memfd_backed(
    regions: &[(GuestAddress, usize)],
    track_dirty_pages: bool,
    huge_pages: HugePageConfig,
) -> Result<Vec<GuestRegionMmap>, MemoryError> {
    let size = regions.iter().map(|&(_, size)| size as u64).sum();
    let memfd_file = create_memfd(size, huge_pages.into())?.into_file();

    create(
        regions.iter().copied(),
        libc::MAP_SHARED | huge_pages.mmap_flags(),
        Some(memfd_file),
        track_dirty_pages,
    )
}

/// Creates a GuestMemoryMmap from raw regions.
pub fn anonymous(
    regions: impl Iterator<Item = (GuestAddress, usize)>,
    track_dirty_pages: bool,
    huge_pages: HugePageConfig,
) -> Result<Vec<GuestRegionMmap>, MemoryError> {
    create(
        regions,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | huge_pages.mmap_flags(),
        None,
        track_dirty_pages,
    )
}

/// Creates a GuestMemoryMmap given a `file` containing the data
/// and a `state` containing mapping information.
pub fn snapshot_file(
    file: File,
    regions: impl Iterator<Item = (GuestAddress, usize)>,
    track_dirty_pages: bool,
) -> Result<Vec<GuestRegionMmap>, MemoryError> {
    let regions: Vec<_> = regions.collect();
    let memory_size = regions
        .iter()
        .try_fold(0u64, |acc, (_, size)| acc.checked_add(*size as u64))
        .ok_or(MemoryError::OffsetTooLarge)?;
    let file_size = file.metadata().map_err(MemoryError::FileMetadata)?.len();

    // ensure we do not mmap beyond EOF. The kernel would allow that but a SIGBUS is triggered
    // on an attempted access to a page of the buffer that lies beyond the end of the mapped file.
    if memory_size > file_size {
        return Err(MemoryError::OffsetTooLarge);
    }

    create(
        regions.into_iter(),
        libc::MAP_PRIVATE,
        Some(file),
        track_dirty_pages,
    )
}

/// Defines the interface for snapshotting memory.
pub trait GuestMemoryExtension
where
    Self: Sized,
{
    /// Describes GuestMemoryMmap through a GuestMemoryState struct.
    fn describe(&self) -> GuestMemoryState;

    /// Mark memory range as dirty
    fn mark_dirty(&self, addr: GuestAddress, len: usize);

    /// Dumps all contents of GuestMemoryMmap to a writer.
    fn dump<T: WriteVolatile + std::io::Seek>(&self, writer: &mut T) -> Result<(), MemoryError>;

    /// Dumps all pages of GuestMemoryMmap present in `dirty_bitmap` to a writer.
    fn dump_dirty<T: WriteVolatile + std::io::Seek>(
        &self,
        writer: &mut T,
        dirty_bitmap: &DirtyBitmap,
    ) -> Result<(), MemoryError>;

    /// Resets all the memory region bitmaps
    fn reset_dirty(&self);

    /// Store the dirty bitmap in internal store
    fn store_dirty_bitmap(&self, dirty_bitmap: &DirtyBitmap, page_size: usize);

    /// Apply a function to each region in a memory range
    fn try_for_each_region_in_range<F>(
        &self,
        addr: GuestAddress,
        range_len: usize,
        f: F,
    ) -> Result<(), GuestMemoryError>
    where
        F: FnMut(&GuestRegionMmapExt, MemoryRegionAddress, usize) -> Result<(), GuestMemoryError>;

    /// Discards a memory range, freeing up memory pages
    fn discard_range(&self, addr: GuestAddress, range_len: usize) -> Result<(), GuestMemoryError>;
}

/// State of a guest memory region saved to file/buffer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestMemoryRegionState {
    // This should have been named `base_guest_addr` since it's _guest_ addr, but for
    // backward compatibility we have to keep this name. At least this comment should help.
    /// Base GuestAddress.
    pub base_address: u64,
    /// Region size.
    pub size: usize,
    /// Region type
    pub region_type: GuestRegionType,
    /// Plugged/unplugged status of each slot
    pub plugged: Vec<bool>,
}

/// Describes guest memory regions and their snapshot file mappings.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestMemoryState {
    /// List of regions.
    pub regions: Vec<GuestMemoryRegionState>,
}

impl GuestMemoryState {
    /// Turns this [`GuestMemoryState`] into a description of guest memory regions as understood
    /// by the creation functions of [`GuestMemoryExtensions`]
    pub fn regions(&self) -> impl Iterator<Item = (GuestAddress, usize)> + '_ {
        self.regions
            .iter()
            .map(|region| (GuestAddress(region.base_address), region.size))
    }
}

impl GuestMemoryExtension for GuestMemoryMmap {
    /// Describes GuestMemoryMmap through a GuestMemoryState struct.
    fn describe(&self) -> GuestMemoryState {
        let mut guest_memory_state = GuestMemoryState::default();
        self.iter().for_each(|region| {
            guest_memory_state.regions.push(GuestMemoryRegionState {
                base_address: region.start_addr().0,
                size: u64_to_usize(region.len()),
                region_type: region.region_type,
                plugged: region.plugged.lock().unwrap().iter().by_vals().collect(),
            });
        });
        guest_memory_state
    }

    /// Mark memory range as dirty
    fn mark_dirty(&self, addr: GuestAddress, len: usize) {
        // ignore invalid ranges using .flatten()
        for slice in self.get_slices(addr, len).flatten() {
            slice.bitmap().mark_dirty(0, slice.len());
        }
    }

    /// Dumps all contents of GuestMemoryMmap to a writer.
    fn dump<T: WriteVolatile + std::io::Seek>(&self, writer: &mut T) -> Result<(), MemoryError> {
        self.iter()
            .flat_map(|region| region.slots())
            .try_for_each(|(mem_slot, plugged)| {
                if !plugged {
                    let ilen = i64::try_from(mem_slot.slice.len()).unwrap();
                    writer.seek(SeekFrom::Current(ilen)).unwrap();
                } else {
                    writer.write_all_volatile(&mem_slot.slice)?;
                }
                Ok(())
            })
            .map_err(MemoryError::WriteMemory)
    }

    /// Dumps all pages of GuestMemoryMmap present in `dirty_bitmap` to a writer.
    fn dump_dirty<T: WriteVolatile + std::io::Seek>(
        &self,
        writer: &mut T,
        dirty_bitmap: &DirtyBitmap,
    ) -> Result<(), MemoryError> {
        let page_size = get_page_size().map_err(MemoryError::PageSize)?;

        let write_result =
            self.iter()
                .flat_map(|region| region.slots())
                .try_for_each(|(mem_slot, plugged)| {
                    if !plugged {
                        let ilen = i64::try_from(mem_slot.slice.len()).unwrap();
                        writer.seek(SeekFrom::Current(ilen)).unwrap();
                    } else {
                        let kvm_bitmap = dirty_bitmap.get(&mem_slot.slot).unwrap();
                        mem_slot.dump_dirty(writer, kvm_bitmap, page_size)?;
                    }
                    Ok(())
                });

        if write_result.is_err() {
            self.store_dirty_bitmap(dirty_bitmap, page_size);
        } else {
            self.reset_dirty();
        }

        write_result.map_err(MemoryError::WriteMemory)
    }

    /// Resets all the memory region bitmaps
    fn reset_dirty(&self) {
        self.iter().for_each(|region| {
            if let Some(bitmap) = (**region).bitmap() {
                bitmap.reset();
            }
        })
    }

    /// Stores the dirty bitmap inside into the internal bitmap
    fn store_dirty_bitmap(&self, dirty_bitmap: &DirtyBitmap, page_size: usize) {
        self.iter()
            .flat_map(|region| region.plugged_slots())
            .for_each(|mem_slot| {
                let kvm_bitmap = dirty_bitmap.get(&mem_slot.slot).unwrap();
                let firecracker_bitmap = mem_slot.slice.bitmap();

                for (i, v) in kvm_bitmap.iter().enumerate() {
                    for j in 0..64 {
                        let is_kvm_page_dirty = ((v >> j) & 1u64) != 0u64;

                        if is_kvm_page_dirty {
                            let page_offset = ((i * 64) + j) * page_size;

                            firecracker_bitmap.mark_dirty(page_offset, 1)
                        }
                    }
                }
            });
    }

    fn try_for_each_region_in_range<F>(
        &self,
        addr: GuestAddress,
        range_len: usize,
        mut f: F,
    ) -> Result<(), GuestMemoryError>
    where
        F: FnMut(&GuestRegionMmapExt, MemoryRegionAddress, usize) -> Result<(), GuestMemoryError>,
    {
        let mut cur = addr;
        let mut remaining = range_len;

        // iterate over all adjacent consecutive regions in range
        while let Some(region) = self.find_region(cur) {
            let start = region.to_region_addr(cur).unwrap();
            let len = std::cmp::min(
                // remaining bytes inside the region
                u64_to_usize(region.len() - start.raw_value()),
                // remaning bytes to discard
                remaining,
            );

            f(region, start, len)?;

            remaining -= len;
            if remaining == 0 {
                return Ok(());
            }

            cur = cur
                .checked_add(len as u64)
                .ok_or(GuestMemoryError::GuestAddressOverflow)?;
        }
        // if we exit the loop because we didn't find a region, return an error
        Err(GuestMemoryError::InvalidGuestAddress(cur))
    }

    fn discard_range(&self, addr: GuestAddress, range_len: usize) -> Result<(), GuestMemoryError> {
        self.try_for_each_region_in_range(addr, range_len, |region, start, len| {
            region.discard_range(start, len)
        })
    }
}

fn create_memfd(
    mem_size: u64,
    hugetlb_size: Option<memfd::HugetlbSize>,
) -> Result<memfd::Memfd, MemoryError> {
    // Create a memfd.
    let opts = memfd::MemfdOptions::default()
        .hugetlb(hugetlb_size)
        .allow_sealing(true);
    let mem_file = opts.create("guest_mem").map_err(MemoryError::Memfd)?;

    // Resize to guest mem size.
    mem_file
        .as_file()
        .set_len(mem_size)
        .map_err(MemoryError::MemfdSetLen)?;

    // Add seals to prevent further resizing.
    let mut seals = memfd::SealsHashSet::new();
    seals.insert(memfd::FileSeal::SealShrink);
    seals.insert(memfd::FileSeal::SealGrow);
    mem_file.add_seals(&seals).map_err(MemoryError::Memfd)?;

    // Prevent further sealing changes.
    mem_file
        .add_seal(memfd::FileSeal::SealSeal)
        .map_err(MemoryError::Memfd)?;

    Ok(mem_file)
}

/// Test utilities
pub mod test_utils {
    use super::*;

    /// Converts a vec of GuestRegionMmap into a GuestMemoryMmap using GuestRegionMmapExt
    pub fn into_region_ext(regions: Vec<GuestRegionMmap>) -> GuestMemoryMmap {
        GuestMemoryMmap::from_regions(
            regions
                .into_iter()
                .zip(0u32..) // assign dummy slots
                .map(|(region, slot)| GuestRegionMmapExt::dram_from_mmap_region(region, slot))
                .collect(),
        )
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]

    use std::collections::HashMap;
    use std::io::{Read, Seek, Write};

    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::snapshot::Snapshot;
    use crate::test_utils::single_region_mem;
    use crate::utils::{get_page_size, mib_to_bytes};
    use crate::vstate::memory::test_utils::into_region_ext;

    #[test]
    fn test_anonymous() {
        for dirty_page_tracking in [true, false] {
            let region_size = 0x10000;
            let regions = vec![
                (GuestAddress(0x0), region_size),
                (GuestAddress(0x10000), region_size),
                (GuestAddress(0x20000), region_size),
                (GuestAddress(0x30000), region_size),
            ];

            let guest_memory = anonymous(
                regions.into_iter(),
                dirty_page_tracking,
                HugePageConfig::None,
            )
            .unwrap();
            guest_memory.iter().for_each(|region| {
                assert_eq!(region.bitmap().is_some(), dirty_page_tracking);
            });
        }
    }

    #[test]
    fn test_snapshot_file_success() {
        for dirty_page_tracking in [true, false] {
            let page_size = 0x1000;
            let mut file = TempFile::new().unwrap().into_file();
            file.set_len(page_size as u64).unwrap();
            file.write_all(&vec![0x42u8; page_size]).unwrap();

            let regions = vec![(GuestAddress(0), page_size)];
            let guest_regions =
                snapshot_file(file, regions.into_iter(), dirty_page_tracking).unwrap();
            assert_eq!(guest_regions.len(), 1);
            guest_regions.iter().for_each(|region| {
                assert_eq!(region.bitmap().is_some(), dirty_page_tracking);
            });
        }
    }

    #[test]
    fn test_snapshot_file_multiple_regions() {
        let page_size = 0x1000;
        let total_size = 3 * page_size;
        let mut file = TempFile::new().unwrap().into_file();
        file.set_len(total_size as u64).unwrap();
        file.write_all(&vec![0x42u8; total_size]).unwrap();

        let regions = vec![
            (GuestAddress(0), page_size),
            (GuestAddress(0x10000), page_size),
            (GuestAddress(0x20000), page_size),
        ];
        let guest_regions = snapshot_file(file, regions.into_iter(), false).unwrap();
        assert_eq!(guest_regions.len(), 3);
    }

    #[test]
    fn test_snapshot_file_offset_too_large() {
        let page_size = 0x1000;
        let mut file = TempFile::new().unwrap().into_file();
        file.set_len(page_size as u64).unwrap();
        file.write_all(&vec![0x42u8; page_size]).unwrap();

        let regions = vec![(GuestAddress(0), 2 * page_size)];
        let result = snapshot_file(file, regions.into_iter(), false);
        assert!(matches!(result.unwrap_err(), MemoryError::OffsetTooLarge));
    }

    #[test]
    fn test_mark_dirty() {
        let page_size = get_page_size().unwrap();
        let region_size = page_size * 3;

        let regions = vec![
            (GuestAddress(0), region_size),                      // pages 0-2
            (GuestAddress(region_size as u64), region_size),     // pages 3-5
            (GuestAddress(region_size as u64 * 2), region_size), // pages 6-8
        ];
        let guest_memory =
            into_region_ext(anonymous(regions.into_iter(), true, HugePageConfig::None).unwrap());

        let dirty_map = [
            // page 0: not dirty
            (0, page_size, false),
            // pages 1-2: dirty range in one region
            (page_size, page_size * 2, true),
            // page 3: not dirty
            (page_size * 3, page_size, false),
            // pages 4-7: dirty range across 2 regions,
            (page_size * 4, page_size * 4, true),
            // page 8: not dirty
            (page_size * 8, page_size, false),
        ];

        // Mark dirty memory
        for (addr, len, dirty) in &dirty_map {
            if *dirty {
                guest_memory.mark_dirty(GuestAddress(*addr as u64), *len);
            }
        }

        // Check that the dirty memory was set correctly
        for (addr, len, dirty) in &dirty_map {
            for slice in guest_memory
                .get_slices(GuestAddress(*addr as u64), *len)
                .flatten()
            {
                for i in 0..slice.len() {
                    assert_eq!(slice.bitmap().dirty_at(i), *dirty);
                }
            }
        }
    }

    fn check_serde<M: GuestMemoryExtension>(guest_memory: &M) {
        let original_state = guest_memory.describe();

        // Test direct bitcode serialization
        let serialized_data = bitcode::serialize(&original_state).unwrap();
        let restored_state: GuestMemoryState = bitcode::deserialize(&serialized_data).unwrap();
        assert_eq!(original_state, restored_state);

        // Test with Snapshot wrapper
        let snapshot_data = bitcode::serialize(&Snapshot::new(original_state.clone())).unwrap();
        let restored_snapshot = Snapshot::load_without_crc_check(&snapshot_data).unwrap();
        assert_eq!(original_state, restored_snapshot.data);
    }

    #[test]
    fn test_serde() {
        let page_size = get_page_size().unwrap();
        let region_size = page_size * 3;

        // Test with a single region
        let guest_memory = into_region_ext(
            anonymous(
                [(GuestAddress(0), region_size)].into_iter(),
                false,
                HugePageConfig::None,
            )
            .unwrap(),
        );
        check_serde(&guest_memory);

        // Test with some regions
        let regions = vec![
            (GuestAddress(0), region_size),                      // pages 0-2
            (GuestAddress(region_size as u64), region_size),     // pages 3-5
            (GuestAddress(region_size as u64 * 2), region_size), // pages 6-8
        ];
        let guest_memory =
            into_region_ext(anonymous(regions.into_iter(), true, HugePageConfig::None).unwrap());
        check_serde(&guest_memory);
    }

    #[test]
    fn test_describe() {
        let page_size: usize = get_page_size().unwrap();

        // Two regions of one page each, with a one page gap between them.
        let mem_regions = [
            (GuestAddress(0), page_size),
            (GuestAddress(page_size as u64 * 2), page_size),
        ];
        let guest_memory = into_region_ext(
            anonymous(mem_regions.into_iter(), true, HugePageConfig::None).unwrap(),
        );

        let expected_memory_state = GuestMemoryState {
            regions: vec![
                GuestMemoryRegionState {
                    base_address: 0,
                    size: page_size,
                    region_type: GuestRegionType::Dram,
                    plugged: vec![true],
                },
                GuestMemoryRegionState {
                    base_address: page_size as u64 * 2,
                    size: page_size,
                    region_type: GuestRegionType::Dram,
                    plugged: vec![true],
                },
            ],
        };

        let actual_memory_state = guest_memory.describe();
        assert_eq!(expected_memory_state, actual_memory_state);

        // Two regions of three pages each, with a one page gap between them.
        let mem_regions = [
            (GuestAddress(0), page_size * 3),
            (GuestAddress(page_size as u64 * 4), page_size * 3),
        ];
        let guest_memory = into_region_ext(
            anonymous(mem_regions.into_iter(), true, HugePageConfig::None).unwrap(),
        );

        let expected_memory_state = GuestMemoryState {
            regions: vec![
                GuestMemoryRegionState {
                    base_address: 0,
                    size: page_size * 3,
                    region_type: GuestRegionType::Dram,
                    plugged: vec![true],
                },
                GuestMemoryRegionState {
                    base_address: page_size as u64 * 4,
                    size: page_size * 3,
                    region_type: GuestRegionType::Dram,
                    plugged: vec![true],
                },
            ],
        };

        let actual_memory_state = guest_memory.describe();
        assert_eq!(expected_memory_state, actual_memory_state);
    }

    #[test]
    fn test_dump() {
        let page_size = get_page_size().unwrap();

        // Two regions of two pages each, with a one page gap between them.
        let region_1_address = GuestAddress(0);
        let region_2_address = GuestAddress(page_size as u64 * 3);
        let region_size = page_size * 2;
        let mem_regions = [
            (region_1_address, region_size),
            (region_2_address, region_size),
        ];
        let guest_memory = into_region_ext(
            anonymous(mem_regions.into_iter(), true, HugePageConfig::None).unwrap(),
        );
        // Check that Firecracker bitmap is clean.
        guest_memory.iter().for_each(|r| {
            assert!(!r.bitmap().dirty_at(0));
            assert!(!r.bitmap().dirty_at(1));
        });

        // Fill the first region with 1s and the second with 2s.
        let first_region = vec![1u8; region_size];
        guest_memory.write(&first_region, region_1_address).unwrap();

        let second_region = vec![2u8; region_size];
        guest_memory
            .write(&second_region, region_2_address)
            .unwrap();

        let memory_state = guest_memory.describe();

        // dump the full memory.
        let mut memory_file = TempFile::new().unwrap().into_file();
        guest_memory.dump(&mut memory_file).unwrap();

        let restored_guest_memory =
            into_region_ext(snapshot_file(memory_file, memory_state.regions(), false).unwrap());

        // Check that the region contents are the same.
        let mut restored_region = vec![0u8; page_size * 2];
        restored_guest_memory
            .read(restored_region.as_mut_slice(), region_1_address)
            .unwrap();
        assert_eq!(first_region, restored_region);

        restored_guest_memory
            .read(restored_region.as_mut_slice(), region_2_address)
            .unwrap();
        assert_eq!(second_region, restored_region);
    }

    #[test]
    fn test_dump_dirty() {
        let page_size = get_page_size().unwrap();

        // Two regions of two pages each, with a one page gap between them.
        let region_1_address = GuestAddress(0);
        let region_2_address = GuestAddress(page_size as u64 * 3);
        let region_size = page_size * 2;
        let mem_regions = [
            (region_1_address, region_size),
            (region_2_address, region_size),
        ];
        let guest_memory = into_region_ext(
            anonymous(mem_regions.into_iter(), true, HugePageConfig::None).unwrap(),
        );
        // Check that Firecracker bitmap is clean.
        guest_memory.iter().for_each(|r| {
            assert!(!r.bitmap().dirty_at(0));
            assert!(!r.bitmap().dirty_at(1));
        });

        // Fill the first region with 1s and the second with 2s.
        let first_region = vec![1u8; region_size];
        guest_memory.write(&first_region, region_1_address).unwrap();

        let second_region = vec![2u8; region_size];
        guest_memory
            .write(&second_region, region_2_address)
            .unwrap();

        let memory_state = guest_memory.describe();

        // Dump only the dirty pages.
        // First region pages: [dirty, clean]
        // Second region pages: [clean, dirty]
        let mut dirty_bitmap: DirtyBitmap = HashMap::new();
        dirty_bitmap.insert(0, vec![0b01]);
        dirty_bitmap.insert(1, vec![0b10]);

        let mut file = TempFile::new().unwrap().into_file();
        guest_memory.dump_dirty(&mut file, &dirty_bitmap).unwrap();

        // We can restore from this because this is the first dirty dump.
        let restored_guest_memory =
            into_region_ext(snapshot_file(file, memory_state.regions(), false).unwrap());

        // Check that the region contents are the same.
        let mut restored_region = vec![0u8; region_size];
        restored_guest_memory
            .read(restored_region.as_mut_slice(), region_1_address)
            .unwrap();
        assert_eq!(first_region, restored_region);

        restored_guest_memory
            .read(restored_region.as_mut_slice(), region_2_address)
            .unwrap();
        assert_eq!(second_region, restored_region);

        // Dirty the memory and dump again
        let file = TempFile::new().unwrap();
        let mut reader = file.into_file();
        let zeros = vec![0u8; page_size];
        let ones = vec![1u8; page_size];
        let twos = vec![2u8; page_size];

        // Firecracker Bitmap
        // First region pages: [dirty, clean]
        // Second region pages: [clean, clean]
        guest_memory
            .write(&twos, GuestAddress(page_size as u64))
            .unwrap();

        guest_memory.dump_dirty(&mut reader, &dirty_bitmap).unwrap();

        // Check that only the dirty regions are dumped.
        let mut diff_file_content = Vec::new();
        let expected_first_region = [
            ones.as_slice(),
            twos.as_slice(),
            zeros.as_slice(),
            twos.as_slice(),
        ]
        .concat();
        reader.seek(SeekFrom::Start(0)).unwrap();
        reader.read_to_end(&mut diff_file_content).unwrap();
        assert_eq!(expected_first_region, diff_file_content);
    }

    #[test]
    fn test_store_dirty_bitmap() {
        let page_size = get_page_size().unwrap();

        // Two regions of three pages each, with a one page gap between them.
        let region_1_address = GuestAddress(0);
        let region_2_address = GuestAddress(page_size as u64 * 4);
        let region_size = page_size * 3;
        let mem_regions = [
            (region_1_address, region_size),
            (region_2_address, region_size),
        ];
        let guest_memory = into_region_ext(
            anonymous(mem_regions.into_iter(), true, HugePageConfig::None).unwrap(),
        );

        // Check that Firecracker bitmap is clean.
        guest_memory.iter().for_each(|r| {
            assert!(!r.bitmap().dirty_at(0));
            assert!(!r.bitmap().dirty_at(page_size));
            assert!(!r.bitmap().dirty_at(page_size * 2));
        });

        let mut dirty_bitmap: DirtyBitmap = HashMap::new();
        dirty_bitmap.insert(0, vec![0b101]);
        dirty_bitmap.insert(1, vec![0b101]);

        guest_memory.store_dirty_bitmap(&dirty_bitmap, page_size);

        // Assert that the bitmap now reports as being dirty maching the dirty bitmap
        guest_memory.iter().for_each(|r| {
            assert!(r.bitmap().dirty_at(0));
            assert!(!r.bitmap().dirty_at(page_size));
            assert!(r.bitmap().dirty_at(page_size * 2));
        });
    }

    #[test]
    fn test_create_memfd() {
        let size_bytes = mib_to_bytes(1) as u64;

        let memfd = create_memfd(size_bytes, None).unwrap();

        assert_eq!(memfd.as_file().metadata().unwrap().len(), size_bytes);
        memfd.as_file().set_len(0x69).unwrap_err();

        let mut seals = memfd::SealsHashSet::new();
        seals.insert(memfd::FileSeal::SealGrow);
        memfd.add_seals(&seals).unwrap_err();
    }

    /// This asserts that $lhs matches $rhs.
    macro_rules! assert_match {
        ($lhs:expr, $rhs:pat) => {{ assert!(matches!($lhs, $rhs)) }};
    }

    #[test]
    fn test_discard_range() {
        let page_size: usize = 0x1000;
        let mem = single_region_mem(2 * page_size);

        // Fill the memory with ones.
        let ones = vec![1u8; 2 * page_size];
        mem.write(&ones[..], GuestAddress(0)).unwrap();

        // Remove the first page.
        mem.discard_range(GuestAddress(0), page_size).unwrap();

        // Check that the first page is zeroed.
        let mut actual_page = vec![0u8; page_size];
        mem.read(actual_page.as_mut_slice(), GuestAddress(0))
            .unwrap();
        assert_eq!(vec![0u8; page_size], actual_page);
        // Check that the second page still contains ones.
        mem.read(actual_page.as_mut_slice(), GuestAddress(page_size as u64))
            .unwrap();
        assert_eq!(vec![1u8; page_size], actual_page);

        // Malformed range: the len is too big.
        assert_match!(
            mem.discard_range(GuestAddress(0), 0x10000).unwrap_err(),
            GuestMemoryError::InvalidGuestAddress(_)
        );

        // Region not mapped.
        assert_match!(
            mem.discard_range(GuestAddress(0x10000), 0x10).unwrap_err(),
            GuestMemoryError::InvalidGuestAddress(_)
        );

        // Madvise fail: the guest address is not aligned to the page size.
        assert_match!(
            mem.discard_range(GuestAddress(0x20), page_size)
                .unwrap_err(),
            GuestMemoryError::IOError(_)
        );
    }

    #[test]
    fn test_discard_range_on_file() {
        let page_size: usize = 0x1000;
        let mut memory_file = TempFile::new().unwrap().into_file();
        memory_file.set_len(2 * page_size as u64).unwrap();
        memory_file.write_all(&vec![2u8; 2 * page_size]).unwrap();
        let mem = into_region_ext(
            snapshot_file(
                memory_file,
                std::iter::once((GuestAddress(0), 2 * page_size)),
                false,
            )
            .unwrap(),
        );

        // Fill the memory with ones.
        let ones = vec![1u8; 2 * page_size];
        mem.write(&ones[..], GuestAddress(0)).unwrap();

        // Remove the first page.
        mem.discard_range(GuestAddress(0), page_size).unwrap();

        // Check that the first page is zeroed.
        let mut actual_page = vec![0u8; page_size];
        mem.read(actual_page.as_mut_slice(), GuestAddress(0))
            .unwrap();
        assert_eq!(vec![0u8; page_size], actual_page);
        // Check that the second page still contains ones.
        mem.read(actual_page.as_mut_slice(), GuestAddress(page_size as u64))
            .unwrap();
        assert_eq!(vec![1u8; page_size], actual_page);

        // Malformed range: the len is too big.
        assert_match!(
            mem.discard_range(GuestAddress(0), 0x10000).unwrap_err(),
            GuestMemoryError::InvalidGuestAddress(_)
        );

        // Region not mapped.
        assert_match!(
            mem.discard_range(GuestAddress(0x10000), 0x10).unwrap_err(),
            GuestMemoryError::InvalidGuestAddress(_)
        );

        // Mmap fail: the guest address is not aligned to the page size.
        assert_match!(
            mem.discard_range(GuestAddress(0x20), page_size)
                .unwrap_err(),
            GuestMemoryError::IOError(_)
        );
    }
}

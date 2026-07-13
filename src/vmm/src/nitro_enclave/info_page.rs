// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Nitro Enclave info page: header, TOC, and serial ring buffer reader.
//!
//! The info page is a 2 MiB-aligned shared memory region containing
//! a TOC with entries for serial ring buffers. The enclave VMM writes device
//! state here; the parent VMM polls it.

use std::io;
use std::mem::size_of;
use std::num::Wrapping;

use vm_memory::{
    ByteValued, Bytes, GuestMemoryRegion, MemoryRegionAddress, VolatileMemoryError, VolatileSlice,
    WriteVolatile,
};

use super::ne_ioctl::EnclaveFd;
use crate::logger::warn;
use crate::utils::u64_to_usize;
use crate::vstate::memory::{AtomicBitmap, BS, GuestRegionMmap, MemoryError};

/// Info page magic number (`NISC` in little-endian).
pub const INFO_PAGE_MAGIC: u32 = 0x5343_494E;

/// Info page size (2 MiB).
pub const INFO_PAGE_SIZE: usize = 2 * 1024 * 1024;

/// TOC entry type for serial ring buffer.
const TOC_TYPE_SERIAL: u16 = 1;

/// TOC entry type for device config mirror.
pub const TOC_TYPE_DEVICE_CONFIG: u16 = 2;

/// Maximum number of TOC entries that fit in the info page.
const MAX_TOC_ENTRIES: usize =
    (INFO_PAGE_SIZE - size_of::<NitroInfoHeader>()) / size_of::<NitroTocEntry>();

/// Maximum number of virtqueues per device in the mirror.
const MAX_VIRTIO_QUEUES: usize = 64;

// ---------------------------------------------------------------------------
// ABI structures shared with the NE driver
// ---------------------------------------------------------------------------

/// Info page header -- lives at the start of the 2 MiB region.
#[repr(C, packed)]
#[derive(Debug, Default, Clone, Copy)]
pub struct NitroInfoHeader {
    /// Magic number, must equal [`INFO_PAGE_MAGIC`].
    pub magic: u32,
    /// Header version.
    pub version: u32,
    /// Number of TOC entries following this header.
    pub num_entries: u32,
    /// CRC32 checksum (reserved, not currently validated).
    pub crc32: u32,
    // toc[] follows immediately in memory
}

// SAFETY: NitroInfoHeader is a #[repr(C, packed)] POD with no padding.
// All members are simple numbers and any value is valid.
unsafe impl ByteValued for NitroInfoHeader {}

/// The `device` arm of a TOC entry's `extra` union, for a
/// `TOC_TYPE_DEVICE_CONFIG` entry: the device's `device_uid` plus reserved
/// words.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TocDeviceExtra {
    /// Device UID assigned by NE_ADD_DEVICE.
    pub device_uid: u64,
    /// Reserved.
    pub reserved: [u64; 3],
}

/// The type-specific `extra` payload of a TOC entry: a 32-byte union whose
/// meaningful arm depends on the entry's `entry_type`.
#[repr(C)]
#[derive(Clone, Copy)]
pub union TocExtra {
    /// Interpretation for a `TOC_TYPE_DEVICE_CONFIG` entry.
    pub device: TocDeviceExtra,
    /// Raw bytes (and the `reserved` arm of the union).
    pub raw: [u8; 32],
}

impl Default for TocExtra {
    fn default() -> Self {
        TocExtra { raw: [0u8; 32] }
    }
}

impl std::fmt::Debug for TocExtra {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // SAFETY: every 32-byte pattern is a valid `raw` arm.
        f.debug_struct("TocExtra")
            .field("raw", unsafe { &self.raw })
            .finish()
    }
}

/// TOC entry describing a region within the info page.
#[repr(C, packed)]
#[derive(Debug, Default, Clone, Copy)]
pub struct NitroTocEntry {
    /// Entry type (1 = serial ring buffer).
    pub entry_type: u16,
    /// Entry flags (reserved).
    pub flags: u16,
    /// Byte offset from the start of the info page.
    pub offset: u32,
    /// Size of the region in bytes.
    pub size: u64,
    /// Type-specific payload (see [`TocExtra`]).
    pub extra: TocExtra,
}

// SAFETY: NitroTocEntry is a #[repr(C, packed)] POD with no padding; every
// member (including the `TocExtra` union, both arms POD and 32 bytes) is valid
// for any byte pattern.
unsafe impl ByteValued for NitroTocEntry {}

const _: () = assert!(
    size_of::<TocExtra>() == 32,
    "TocExtra must be 32 bytes (shared info-page ABI)"
);
const _: () = assert!(
    size_of::<NitroTocEntry>() == 48,
    "NitroTocEntry must be 48 bytes (shared info-page ABI)"
);

impl NitroTocEntry {
    /// The `device` arm of the `extra` union, but only for a
    /// `TOC_TYPE_DEVICE_CONFIG` entry. Returns `None` for any other entry type,
    /// so the union is never misinterpreted.
    fn device_extra(&self) -> Option<TocDeviceExtra> {
        if self.entry_type != TOC_TYPE_DEVICE_CONFIG {
            return None;
        }
        // SAFETY: the entry is a device-config entry, so the producer wrote the
        // `device` arm; any byte pattern is also a valid `TocDeviceExtra` (POD).
        Some(unsafe { self.extra.device })
    }
}

/// Serial ring buffer header — first 8 bytes of a serial TOC region.
#[repr(C, packed)]
#[derive(Debug, Default, Clone, Copy)]
struct SerialRingHeader {
    /// Cumulative bytes written; wraps at u32::MAX.
    write_idx: Wrapping<u32>,
    /// Ring buffer capacity in bytes (data follows immediately).
    capacity: u32,
}

// SAFETY: SerialRingHeader is a #[repr(C, packed)] POD with no padding.
unsafe impl ByteValued for SerialRingHeader {}

/// Per-virtqueue state as mirrored by the VMM in the `VirtioDeviceMirror`.
#[repr(C, packed)]
#[derive(Debug, Default, Clone, Copy)]
pub struct VirtioQueueMirror {
    /// Queue size (number of descriptors).
    pub size: u16,
    /// MSI-X vector assigned to this queue.
    pub msix_vector: u16,
    /// Whether this queue is enabled (1 = enabled by driver).
    pub enable: u16,
    /// Notify offset for this queue.
    pub notify_off: u16,
    // `desc`/`driver`/`device` use the info-page ABI's virtio-1.0 split-queue
    // naming: the driver area holds the available ring, the device area holds
    // the used ring.
    /// Descriptor table GPA.
    pub desc: u64,
    /// Available ring GPA (driver area).
    pub driver: u64,
    /// Used ring GPA (device area).
    pub device: u64,
}

// SAFETY: VirtioQueueMirror is a #[repr(C, packed)] POD.
unsafe impl ByteValued for VirtioQueueMirror {}

/// Common virtio config state in the `VirtioDeviceMirror`.
#[repr(C, packed)]
#[derive(Debug, Default, Clone, Copy)]
pub struct VirtioCommonCfgMirror {
    /// Device feature page selector.
    pub device_feature_select: u32,
    /// Device features (selected page).
    pub device_feature: u32,
    /// Driver feature page selector.
    pub driver_feature_select: u32,
    /// Driver features (selected page).
    pub driver_feature: u32,
    /// MSI-X config vector.
    pub msix_config: u16,
    /// Number of queues.
    pub num_queues: u16,
    /// Device status. Bit-for-bit the virtio device status register; the
    /// DRIVER_OK bit (0x04) indicates the guest driver finished initialization.
    pub device_status: u8,
    /// Config generation counter.
    pub config_generation: u8,
    /// Currently selected queue.
    pub queue_select: u16,
}

// SAFETY: VirtioCommonCfgMirror is a #[repr(C, packed)] POD.
unsafe impl ByteValued for VirtioCommonCfgMirror {}

/// Per-device entry header preceding the mirror in a device-config region.
///
/// A 128-byte header whose mirror follows at offset
/// `size_of::<DeviceEntryHeader>()`.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct DeviceEntryHeader {
    /// Reset counter (incremented by the VMM on device reset).
    pub reset_count: u64,
    /// Generation counter, written after each mirror update.
    pub generation: u32,
    /// Reserved padding to a 128-byte header.
    pub reserved: [u8; 116],
}

// SAFETY: DeviceEntryHeader is a #[repr(C, packed)] POD.
unsafe impl ByteValued for DeviceEntryHeader {}

const _: () = assert!(
    size_of::<DeviceEntryHeader>() == 128,
    "DeviceEntryHeader must be 128 bytes (shared info-page ABI)"
);

/// Complete device mirror written by the VMM into the info page.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct VirtioDeviceMirror {
    /// Common virtio PCI config registers.
    pub common: VirtioCommonCfgMirror,
    /// Per-queue state.
    pub queue: [VirtioQueueMirror; MAX_VIRTIO_QUEUES],
    /// Device features (full 64-bit, not page-selected).
    pub device_features: u64,
    /// Driver-acknowledged features (full 64-bit).
    pub driver_features: u64,
    /// Virtio device type ID.
    pub virtio_devid: u16,
    /// Reserved padding.
    pub reserved_pad: [u8; 6],
    /// Device UID assigned by NE_ADD_DEVICE.
    pub device_uid: u64,
    /// Extended device feature bits (bits 64-511).
    pub device_features_ext: [u8; 56],
    /// Extended driver feature bits (bits 64-511).
    pub driver_features_ext: [u8; 56],
}

// SAFETY: VirtioDeviceMirror is a #[repr(C, packed)] POD.
unsafe impl ByteValued for VirtioDeviceMirror {}

const _: () = assert!(
    size_of::<VirtioDeviceMirror>() == 2216,
    "VirtioDeviceMirror must be 2216 bytes (shared info-page ABI)"
);
const _: () = assert!(
    size_of::<VirtioQueueMirror>() == 32,
    "VirtioQueueMirror must be 32 bytes (shared info-page ABI)"
);

/// A `TOC_TYPE_DEVICE_CONFIG` region: the device-entry header followed by the
/// virtio device mirror. Reading the whole entry at the TOC offset avoids any
/// header/mirror offset arithmetic.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct DeviceEntry {
    /// Per-device header (reset/generation counters).
    pub header: DeviceEntryHeader,
    /// The virtio device mirror.
    pub mirror: VirtioDeviceMirror,
}

// SAFETY: DeviceEntry is a #[repr(C, packed)] POD (header + mirror, both POD).
unsafe impl ByteValued for DeviceEntry {}

const _: () = assert!(
    size_of::<DeviceEntry>() == 128 + 2216,
    "DeviceEntry must be 2344 bytes (shared info-page ABI)"
);

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during info page operations.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum InfoPageError {
    /// mmap allocation failed: {0}
    Alloc(MemoryError),
    /// NE_SET_INFO_PAGE ioctl failed: {0}
    Register(io::Error),
    /// invalid info page header magic
    InvalidHeader,
}

/// Errors from draining the info page's serial ring.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum SerialRingError {
    /// serial output is full
    SinkFull,
    /// failed to write serial output: {0}
    Sink(VolatileMemoryError),
    /// info page has no serial ring
    NoRing,
    /// info page TOC entry {entry}: serial ring capacity {capacity} unusable
    BadCapacity {
        /// Index of the offending TOC entry.
        entry: usize,
        /// Capacity the hypervisor declared.
        capacity: u32,
    },
}

impl SerialRingError {
    /// Whether a later poll could succeed. Only a full sink drains later; a
    /// malformed ring or a dead sink will not fix itself.
    pub fn is_retriable(&self) -> bool {
        matches!(self, Self::SinkFull)
    }
}

impl From<VolatileMemoryError> for SerialRingError {
    fn from(e: VolatileMemoryError) -> Self {
        match e {
            VolatileMemoryError::IOError(ref io_err)
                if io_err.kind() == io::ErrorKind::WouldBlock =>
            {
                Self::SinkFull
            }
            other => Self::Sink(other),
        }
    }
}

// ---------------------------------------------------------------------------
// InfoPage -- allocation, registration, and serial ring reading
// ---------------------------------------------------------------------------

/// A 2 MiB-aligned info page shared with the enclave VMM.
#[derive(Debug)]
pub struct InfoPage {
    /// Owning CMA region backing the info page.
    region: GuestRegionMmap,
}

// SAFETY: InfoPage is only accessed via VolatileSlice (volatile reads), never
// through shared references to the underlying memory. Concurrent writes from
// the enclave VMM are observed safely through volatile operations.
unsafe impl Send for InfoPage {}
// SAFETY: See Send impl.
unsafe impl Sync for InfoPage {}

impl InfoPage {
    /// Allocate the 2 MiB info page via CMA on the NE device fd.
    ///
    /// Mapped `PROT_READ`: Firecracker only consumes the info page (the enclave
    /// produces it), so a read-only mapping faults on accidental writes. The NE
    /// driver pins the pages, so the enclave's writable view is unaffected.
    ///
    /// Placed on parent node 0: the info page is shared metadata, not part of the
    /// enclave's NUMA-placed RAM.
    pub fn new(ne_dev_fd: &super::ne_ioctl::NitroEnclavesDevFd) -> Result<Self, InfoPageError> {
        let region = ne_dev_fd
            .allocate_cma_region(
                vm_memory::GuestAddress(0),
                INFO_PAGE_SIZE,
                libc::PROT_READ,
                0,
            )
            .map_err(InfoPageError::Alloc)?;
        Ok(Self { region })
    }

    /// Allocate a 2 MiB-aligned info page for testing without a real NE device.
    ///
    /// Backs it with an owning anonymous region (same ownership model as the
    /// CMA path, minus the device fd), so the mapping frees on drop.
    #[cfg(test)]
    pub fn allocate_anonymous() -> Result<Self, InfoPageError> {
        // A fresh MAP_ANONYMOUS region is already zeroed, so no explicit clear.
        let region = GuestRegionMmap::allocate(
            vm_memory::GuestAddress(0),
            INFO_PAGE_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANONYMOUS | libc::MAP_SHARED,
            None,
            false,
        )
        .map_err(InfoPageError::Alloc)?;
        Ok(Self { region })
    }

    /// Register this info page with the NE kernel driver.
    pub fn register(&self, enclave_fd: &EnclaveFd) -> Result<(), InfoPageError> {
        enclave_fd
            .set_info_page(self.region.as_ptr() as u64, INFO_PAGE_SIZE as u64)
            .map_err(InfoPageError::Register)
    }

    /// Get the userspace address of the info page.
    #[cfg(test)]
    pub fn addr(&self) -> usize {
        self.region.as_ptr() as usize
    }

    /// Returns `true` if the info page header has valid magic.
    #[cfg(test)]
    pub fn header_valid(&self) -> bool {
        self.header().is_some()
    }

    /// Write new serial data since `last_write_idx` directly into `dst`.
    ///
    /// Each chunk is written once, so a sink that accepts only part of the data
    /// does not block the caller. Returns `Ok((cursor, bytes written))`, where
    /// the cursor trails `write_idx` on a short write so the next call resumes
    /// there, and the count is zero when the ring holds nothing new.
    ///
    /// On error, see [`SerialRingError::is_retriable`]: a full sink drains on a
    /// later poll, whereas a malformed ring means a broken hypervisor (it
    /// publishes one before `NE_START_ENCLAVE` returns, so the console only
    /// ever polls a populated page).
    pub fn write_serial_since<W: WriteVolatile>(
        &self,
        last_write_idx: Wrapping<u32>,
        dst: &mut W,
    ) -> Result<(Wrapping<u32>, u32), SerialRingError> {
        for (i, toc) in self.toc_entries() {
            if toc.entry_type != TOC_TYPE_SERIAL {
                continue;
            }
            let offset = toc.offset as usize;
            let size = u64_to_usize(toc.size);

            // The region must be large enough to hold the ring header.
            if size < size_of::<SerialRingHeader>() {
                warn!("info page TOC entry {i}: size {size} too small for a serial ring");
                continue;
            }
            // `toc.offset`/`toc.size` are hypervisor-controlled; use checked
            // arithmetic so a huge value cannot wrap `usize`, and reject a region
            // that would run past the info page.
            if offset.checked_add(size).is_none_or(|e| e > INFO_PAGE_SIZE) {
                warn!("info page TOC entry {i}: serial region offset={offset} out of bounds");
                continue;
            }
            let vs = self.as_volatile_slice();
            let ring: SerialRingHeader = match vs.read_obj(offset) {
                Ok(r) => r,
                Err(e) => {
                    warn!("info page TOC entry {i}: serial ring read failed: {e}");
                    continue;
                }
            };
            let data_offset = offset + size_of::<SerialRingHeader>();
            let capacity = ring.capacity;
            if capacity == 0 || capacity as usize > size - size_of::<SerialRingHeader>() {
                return Err(SerialRingError::BadCapacity { entry: i, capacity });
            }
            // `write_idx` wraps at u32::MAX, so the delta is a wrapping
            // subtraction; a zero delta means no new data.
            let new_bytes = (ring.write_idx - last_write_idx).0;
            if new_bytes == 0 {
                return Ok((last_write_idx, 0));
            }
            let read_len = new_bytes.min(capacity);
            // Anchor on the oldest surviving byte, `read_len` behind `write_idx`.
            // This is `last_write_idx` normally, but the overwritten start once
            // the ring overflowed (`new_bytes > capacity`). Exact across the u32
            // counter wrap only when capacity is a power of two.
            let anchor = ring.write_idx - Wrapping(read_len);
            let start_pos = anchor.0 % capacity;
            // A drain running off the end of the ring continues at the start, so
            // it takes two writes; `min` keeps the non-wrapping case to one.
            // `start_pos < capacity` and `read_len <= capacity <= INFO_PAGE_SIZE`,
            // so neither sum can overflow u32.
            let first_chunk = (capacity - start_pos).min(read_len);
            let mut written =
                vs.write_volatile_to(data_offset + start_pos as usize, dst, first_chunk as usize)?;
            // Continue into the wrapped part only if the first chunk went out
            // whole, so a short write cannot leave a hole mid-stream. Keep that
            // progress if the remainder is refused; the cursor then trails
            // `write_idx` and the next call reports the error.
            if written == first_chunk as usize && read_len > first_chunk {
                written += vs
                    .write_volatile_to(data_offset, dst, (read_len - first_chunk) as usize)
                    .unwrap_or(0);
            }
            let written = u32::try_from(written).expect("write_volatile_to wrote past read_len");
            return Ok((anchor + Wrapping(written), written));
        }
        Err(SerialRingError::NoRing)
    }

    /// Search the info page for a device mirror matching `device_uid`.
    ///
    /// The device's `device_uid` is carried in the TOC entry's `extra` field,
    /// so the matching entry is found without reading any mirror; only the
    /// matched device's mirror is then read back. Returns the mirror snapshot
    /// if a `TOC_TYPE_DEVICE_CONFIG` entry with the given `device_uid` is
    /// present, or `None` otherwise.
    pub fn find_device_entry(&self, device_uid: u64) -> Option<DeviceEntry> {
        let vs = self.as_volatile_slice();
        let entry_size = size_of::<DeviceEntry>();

        let (i, toc) = self
            .toc_entries()
            .find(|(_, toc)| toc.device_extra().map(|e| e.device_uid) == Some(device_uid))?;

        let offset = toc.offset as usize;
        let size = u64_to_usize(toc.size);

        // The recorded region must be large enough to hold a full DeviceEntry.
        if size < entry_size {
            warn!("info page TOC entry {i}: size {size} too small for a device entry");
            return None;
        }
        // `toc.offset`/`toc.size` are hypervisor-controlled; use checked
        // arithmetic so a large value cannot wrap `usize`, and reject an entry
        // that would run past the info page.
        if offset
            .checked_add(entry_size)
            .is_none_or(|e| e > INFO_PAGE_SIZE)
        {
            warn!("info page TOC entry {i}: device entry offset {offset} out of bounds");
            return None;
        }

        match vs.read_obj::<DeviceEntry>(offset) {
            Ok(entry) => Some(entry),
            Err(e) => {
                warn!("info page TOC entry {i}: device entry read failed: {e}");
                None
            }
        }
    }

    fn as_volatile_slice(&self) -> VolatileSlice<'_, BS<'_, Option<AtomicBitmap>>> {
        // The region spans the whole INFO_PAGE_SIZE at offset 0, so this slice
        // covers the entire info page and cannot fail.
        self.region
            .get_slice(MemoryRegionAddress(0), INFO_PAGE_SIZE)
            .expect("info page region covers INFO_PAGE_SIZE at offset 0")
    }

    /// Read the info page header via volatile read.
    ///
    /// Returns `None` if the magic number does not match.
    fn header(&self) -> Option<NitroInfoHeader> {
        let header: NitroInfoHeader = self.as_volatile_slice().read_obj(0).ok()?;
        if header.magic != INFO_PAGE_MAGIC {
            return None;
        }
        Some(header)
    }

    /// Iterate the valid TOC entries of the info page.
    ///
    /// Reads and validates the header, clamps the entry count to
    /// [`MAX_TOC_ENTRIES`], and yields `(index, entry)` for each readable TOC
    /// entry. Yields nothing if the header is invalid.
    fn toc_entries(&self) -> impl Iterator<Item = (usize, NitroTocEntry)> + '_ {
        let num = self
            .header()
            .map_or(0, |h| (h.num_entries as usize).min(MAX_TOC_ENTRIES));
        (0..num).filter_map(move |i| self.toc_entry(i).map(|toc| (i, toc)))
    }

    /// Read a TOC entry by index via volatile read.
    ///
    /// Returns `None` if the entry would be out of bounds.
    fn toc_entry(&self, index: usize) -> Option<NitroTocEntry> {
        let toc_start = size_of::<NitroInfoHeader>();
        let entry_offset = toc_start + index * size_of::<NitroTocEntry>();
        self.as_volatile_slice().read_obj(entry_offset).ok()
    }

    #[cfg(test)]
    /// Build a test info page from a caller-prepared buffer: copy `ptr`'s
    /// `INFO_PAGE_SIZE` bytes into a fresh owning (anonymous) region so the
    /// resulting `InfoPage` owns and frees its mapping like production. The
    /// caller's temporary buffer is theirs to free (it's a private mmap).
    pub(crate) fn from_raw_ptr(ptr: *mut u8) -> Self {
        let page = Self::allocate_anonymous().expect("mock info-page region");
        // SAFETY: both buffers are valid for INFO_PAGE_SIZE bytes and do not
        // overlap (freshly, separately mmap'd).
        unsafe {
            std::ptr::copy_nonoverlapping(ptr, page.region.as_ptr(), INFO_PAGE_SIZE);
        }
        page
    }
}

/// Create a test info page with a serial ring buffer for unit tests.
///
/// Allocates an anonymous page, writes a valid header + TOC + ring buffer,
/// and returns an `InfoPage` wrapping it.
#[cfg(test)]
#[allow(clippy::undocumented_unsafe_blocks)]
pub(crate) fn make_test_page(write_idx: u32, capacity: u32, data: &[u8]) -> InfoPage {
    use std::ptr;
    let ptr = unsafe {
        libc::mmap(
            ptr::null_mut(),
            INFO_PAGE_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
            -1,
            0,
        )
    };
    assert_ne!(ptr, libc::MAP_FAILED);
    let base = ptr.cast::<u8>();
    let header = NitroInfoHeader {
        magic: INFO_PAGE_MAGIC,
        version: 1,
        num_entries: 1,
        crc32: 0,
    };
    unsafe { ptr::write(base.cast::<NitroInfoHeader>(), header) };
    let serial_data_offset: u32 = 4096;
    let serial_region_size: u64 = (capacity as u64) + 8;
    let toc = NitroTocEntry {
        entry_type: TOC_TYPE_SERIAL,
        flags: 0,
        offset: serial_data_offset,
        size: serial_region_size,
        extra: TocExtra::default(),
    };
    let toc_offset = size_of::<NitroInfoHeader>();
    unsafe { ptr::write(base.add(toc_offset).cast::<NitroTocEntry>(), toc) };
    let ring_base = unsafe { base.add(serial_data_offset as usize) };
    unsafe {
        ptr::write(ring_base.cast::<u32>(), write_idx);
        ptr::write(ring_base.add(4).cast::<u32>(), capacity);
    }
    if !data.is_empty() {
        let data_base = unsafe { ring_base.add(8) };
        let len = data.len().min(capacity as usize);
        unsafe { ptr::copy_nonoverlapping(data.as_ptr(), data_base, len) };
    }
    InfoPage::from_raw_ptr(base)
}

/// A sink that accepts `accept` more bytes, then fails with `kind`.
#[cfg(test)]
pub(crate) struct PartialSink {
    pub(crate) accept: usize,
    pub(crate) kind: io::ErrorKind,
    pub(crate) written: Vec<u8>,
}

#[cfg(test)]
impl PartialSink {
    pub(crate) fn new(accept: usize, kind: io::ErrorKind) -> Self {
        Self {
            accept,
            kind,
            written: Vec::new(),
        }
    }
}

#[cfg(test)]
impl WriteVolatile for PartialSink {
    fn write_volatile<B: vm_memory::bitmap::BitmapSlice>(
        &mut self,
        buf: &VolatileSlice<'_, B>,
    ) -> Result<usize, VolatileMemoryError> {
        if self.accept == 0 {
            return Err(VolatileMemoryError::IOError(io::Error::from(self.kind)));
        }
        let take = buf.len().min(self.accept);
        let mut tmp = vec![0u8; take];
        buf.subslice(0, take)
            .expect("take <= buf.len()")
            .copy_to(&mut tmp[..]);
        self.written.extend_from_slice(&tmp);
        self.accept -= take;
        Ok(take)
    }
}

/// Builder for an info page with arbitrary TOC entries, for unit tests.
///
/// Unlike [`make_test_page`] (which writes a single serial entry), this lets a
/// test place multiple, malformed, or out-of-bounds TOC entries and device
/// mirrors so the hypervisor-controlled validation paths in `find_device_entry`
/// and `write_serial_since` can be exercised.
#[cfg(test)]
pub(crate) struct TestPageBuilder {
    base: *mut u8,
    entries: Vec<NitroTocEntry>,
}

#[cfg(test)]
#[allow(clippy::undocumented_unsafe_blocks)]
impl TestPageBuilder {
    /// Allocate a fresh anonymous 2 MiB page with a valid header.
    pub(crate) fn new() -> Self {
        use std::ptr;
        let ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                INFO_PAGE_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        assert_ne!(ptr, libc::MAP_FAILED);
        Self {
            base: ptr.cast::<u8>(),
            entries: Vec::new(),
        }
    }

    /// Add a raw TOC entry verbatim (lets tests craft malformed entries).
    pub(crate) fn toc_entry(mut self, entry: NitroTocEntry) -> Self {
        self.entries.push(entry);
        self
    }

    /// Add a serial ring region at `offset` with the given ring contents.
    pub(crate) fn serial(self, offset: u32, write_idx: u32, capacity: u32, data: &[u8]) -> Self {
        let ring_base = unsafe { self.base.add(offset as usize) };
        unsafe {
            std::ptr::write(ring_base.cast::<u32>(), write_idx);
            std::ptr::write(ring_base.add(4).cast::<u32>(), capacity);
        }
        if !data.is_empty() {
            let len = data.len().min(capacity as usize);
            unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), ring_base.add(8), len) };
        }
        self.toc_entry(NitroTocEntry {
            entry_type: TOC_TYPE_SERIAL,
            flags: 0,
            offset,
            size: u64::from(capacity) + size_of::<SerialRingHeader>() as u64,
            extra: TocExtra::default(),
        })
    }

    /// Add a device-config region: a TOC entry of type `TOC_TYPE_DEVICE_CONFIG`
    /// (tagged with the mirror's `device_uid` in its `extra`) plus a
    /// `DeviceEntry` (zeroed header + `mirror`) written at `offset`. `toc_size`
    /// is the size recorded in the TOC entry (let tests pass an undersized value
    /// to exercise the `size < entry_size` rejection independently of placement).
    pub(crate) fn device_mirror(
        self,
        offset: u32,
        toc_size: u64,
        mirror: VirtioDeviceMirror,
    ) -> Self {
        // Copy device_uid out of the packed struct before referencing.
        let uid = mirror.device_uid;
        // SAFETY: DeviceEntryHeader is a POD; all-zero is valid.
        let header: DeviceEntryHeader = unsafe { std::mem::zeroed() };
        let entry = DeviceEntry { header, mirror };
        // Only write the entry when it fits, so out-of-bounds test cases don't
        // scribble past the mapping.
        if offset as usize + size_of::<DeviceEntry>() <= INFO_PAGE_SIZE {
            unsafe { std::ptr::write(self.base.add(offset as usize).cast::<DeviceEntry>(), entry) };
        }
        // Tag the TOC entry's `extra` with the device_uid so find_device_entry
        // locates it without reading the entry.
        let extra = TocExtra {
            device: TocDeviceExtra {
                device_uid: uid,
                reserved: [0; 3],
            },
        };
        self.toc_entry(NitroTocEntry {
            entry_type: TOC_TYPE_DEVICE_CONFIG,
            flags: 0,
            offset,
            size: toc_size,
            extra,
        })
    }

    /// Finalize: write the header (with `num_entries`) and the TOC array.
    pub(crate) fn build(self) -> InfoPage {
        let header = NitroInfoHeader {
            magic: INFO_PAGE_MAGIC,
            version: 1,
            num_entries: u32::try_from(self.entries.len()).unwrap(),
            crc32: 0,
        };
        unsafe { std::ptr::write(self.base.cast::<NitroInfoHeader>(), header) };
        let toc_start = size_of::<NitroInfoHeader>();
        for (i, entry) in self.entries.iter().enumerate() {
            let off = toc_start + i * size_of::<NitroTocEntry>();
            unsafe { std::ptr::write(self.base.add(off).cast::<NitroTocEntry>(), *entry) };
        }
        InfoPage::from_raw_ptr(self.base)
    }
}

/// Minimum TOC `size` `find_device_entry` accepts for a device-config entry
/// (the full `DeviceEntry`). Exposed for cross-module tests.
#[cfg(test)]
pub(crate) const DEVICE_ENTRY_MIN_SIZE: u64 = size_of::<DeviceEntry>() as u64;

/// A zeroed device mirror with the given `device_uid`, for tests.
#[cfg(test)]
pub(crate) fn test_device_mirror(device_uid: u64) -> VirtioDeviceMirror {
    // SAFETY: VirtioDeviceMirror is a `#[repr(C, packed)]` POD (`ByteValued`);
    // all-zero is a valid value.
    let mut mirror: VirtioDeviceMirror = unsafe { std::mem::zeroed() };
    mirror.device_uid = device_uid;
    mirror
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]
    #![allow(clippy::cast_possible_truncation)]

    use std::io::ErrorKind;
    use std::ptr;

    use super::*;

    // A device region placed well clear of the serial region at offset 4096.
    const DEV_OFFSET: u32 = 8192;
    // Minimum TOC size find_device_entry accepts for a device entry.
    const DEV_MIN_SIZE: u64 = DEVICE_ENTRY_MIN_SIZE;

    // 1024 bytes total serial region minus 8-byte ring header (write_idx + capacity fields).
    const TEST_RING_CAPACITY: u32 = 1016;

    #[test]
    fn test_header_valid() {
        // Zeroed page has no valid magic; writing the magic makes it valid.
        let page = InfoPage::allocate_anonymous().unwrap();
        assert!(!page.header_valid());

        // SAFETY: page owns INFO_PAGE_SIZE bytes; write the magic at offset 0.
        unsafe { *page.region.as_ptr().cast::<u32>() = INFO_PAGE_MAGIC };
        assert!(page.header_valid());
    }

    #[test]
    fn test_addr() {
        // addr() returns the region's host pointer.
        let page = InfoPage::allocate_anonymous().unwrap();
        assert_eq!(page.addr(), page.region.as_ptr() as usize);
    }

    #[test]
    fn test_read_serial_since() {
        // Basic read from offset 0.
        let page = make_test_page(5, TEST_RING_CAPACITY, b"hello");
        let mut buf = Vec::new();
        let (new_idx, written) = page.write_serial_since(Wrapping(0), &mut buf).unwrap();
        assert_eq!(new_idx, Wrapping(5));
        assert_eq!(written, 5);
        assert_eq!(&buf, b"hello");

        // Incremental read from offset 5.
        let page = make_test_page(10, TEST_RING_CAPACITY, b"helloworld");
        buf.clear();
        let (new_idx, _) = page.write_serial_since(Wrapping(5), &mut buf).unwrap();
        assert_eq!(new_idx, Wrapping(10));
        assert_eq!(&buf, b"world");

        // No new data when already caught up.
        let page = make_test_page(5, TEST_RING_CAPACITY, b"hello");
        buf.clear();
        assert_eq!(page.write_serial_since(Wrapping(5), &mut buf).unwrap().1, 0);
    }

    #[test]
    fn test_serial_ring_buffer_wrap_around() {
        // write_idx (20) > capacity (16): reader should get at most `capacity` bytes.
        let page = make_test_page(20, 16, b"ABCDEFGHIJKLMNOP");
        let mut buf = Vec::new();
        let (new_idx, _) = page.write_serial_since(Wrapping(0), &mut buf).unwrap();
        assert_eq!(new_idx, Wrapping(20));
        assert_eq!(buf.len(), 16);
    }

    #[test]
    fn test_serial_ring_buffer_overflow_ordering() {
        // 12 bytes into an 8-byte ring: the oldest 4 are overwritten. The 8
        // survivors are stored as "EFGHABCD" (newest wrapped over positions
        // 0..4) and must read back in write order as "ABCDEFGH", not "EFGHABCD".
        let page = make_test_page(12, 8, b"EFGHABCD");
        let mut buf = Vec::new();
        let (new_idx, written) = page.write_serial_since(Wrapping(0), &mut buf).unwrap();
        assert_eq!(new_idx, Wrapping(12));
        assert_eq!(written, 8);
        assert_eq!(&buf, b"ABCDEFGH");
    }

    #[test]
    fn test_write_serial_since_partial_write_resumes() {
        // The sink takes 4 of 11 bytes, so the next call must emit the other 7
        // exactly once.
        let data = b"hello world";
        let page = make_test_page(data.len() as u32, TEST_RING_CAPACITY, data);

        let mut sink = PartialSink::new(4, ErrorKind::WouldBlock);
        let (idx, written) = page.write_serial_since(Wrapping(0), &mut sink).unwrap();
        assert_eq!(written, 4);
        assert_eq!(idx, Wrapping(4));
        assert_eq!(&sink.written, b"hell");

        let mut sink = PartialSink::new(usize::MAX, ErrorKind::WouldBlock);
        let (idx, written) = page.write_serial_since(idx, &mut sink).unwrap();
        assert_eq!(written, 7);
        assert_eq!(idx, Wrapping(data.len() as u32));
        assert_eq!(&sink.written, b"o world");
    }

    #[test]
    fn test_write_serial_since_sink_refuses_everything() {
        // Nothing accepted: the error reaches the caller, which classifies it.
        let data = b"hello";
        let page = make_test_page(data.len() as u32, TEST_RING_CAPACITY, data);

        let mut sink = PartialSink::new(0, ErrorKind::WouldBlock);
        let err = page
            .write_serial_since(Wrapping(0), &mut sink)
            .expect_err("a sink that accepts nothing must report the error");
        assert!(matches!(err, SerialRingError::SinkFull));
        assert!(err.is_retriable());
        assert!(sink.written.is_empty());
    }

    #[test]
    fn test_write_serial_since_partial_write_across_wrap() {
        // Wrapped drain starting at position 4. The sink takes 3 of the 4-byte
        // first chunk, so writing the wrapped part would reorder the stream.
        let page = make_test_page(12, 8, b"EFGHABCD");

        let mut sink = PartialSink::new(3, ErrorKind::WouldBlock);
        let (idx, written) = page.write_serial_since(Wrapping(0), &mut sink).unwrap();
        assert_eq!(written, 3);
        assert_eq!(idx, Wrapping(7));
        assert_eq!(&sink.written, b"ABC");
    }

    #[test]
    fn test_write_serial_since_wrap_keeps_accepted_first_chunk() {
        // Same wrapped drain, but the first chunk goes out whole before the
        // sink refuses, so that progress is kept.
        let page = make_test_page(12, 8, b"EFGHABCD");

        let mut sink = PartialSink::new(4, ErrorKind::WouldBlock);
        let (idx, written) = page.write_serial_since(Wrapping(0), &mut sink).unwrap();
        assert_eq!(written, 4);
        assert_eq!(idx, Wrapping(8));
        assert_eq!(&sink.written, b"ABCD");
    }

    #[test]
    fn test_read_serial_since_write_idx_u32_wrap() {
        // Last poll saw u32::MAX, now sees 3: wrapping delta == 4 new bytes.
        let capacity: u32 = 8;
        let write_idx: u32 = 3;
        let last_write_idx = Wrapping(u32::MAX);

        // The read starts at `last_write_idx % capacity == 7`, so 4 bytes read
        // pos 7 then wrap to pos 0,1,2 -> "H" + "ABC".
        let page = make_test_page(write_idx, capacity, b"ABCDEFGH");
        let mut buf = Vec::new();
        let (new_idx, _) = page.write_serial_since(last_write_idx, &mut buf).unwrap();
        assert_eq!(new_idx, Wrapping(write_idx));
        assert_eq!(&buf, b"HABC");

        buf.clear();
        assert_eq!(
            page.write_serial_since(Wrapping(write_idx), &mut buf)
                .unwrap()
                .1,
            0
        );
    }

    #[test]
    fn test_find_device_entry_match() {
        let page = TestPageBuilder::new()
            .device_mirror(DEV_OFFSET, DEV_MIN_SIZE, test_device_mirror(42))
            .build();
        let entry = page.find_device_entry(42).expect("entry should be found");
        // Copy out of the packed struct before asserting (no unaligned ref).
        let uid = entry.mirror.device_uid;
        assert_eq!(uid, 42);
        // A different uid does not match.
        assert!(page.find_device_entry(43).is_none());
    }

    #[test]
    fn test_find_device_entry_rejects_bad_entries() {
        // size < entry_size: the recorded TOC size is too small for an entry.
        let page = TestPageBuilder::new()
            .device_mirror(DEV_OFFSET, DEV_MIN_SIZE - 1, test_device_mirror(1))
            .build();
        assert!(page.find_device_entry(1).is_none());

        // entry_end > INFO_PAGE_SIZE: offset so high the entry runs off the page.
        let bad_offset = (INFO_PAGE_SIZE - 16) as u32;
        let page = TestPageBuilder::new()
            .device_mirror(bad_offset, DEV_MIN_SIZE, test_device_mirror(2))
            .build();
        assert!(page.find_device_entry(2).is_none());

        // Wrong entry_type (serial) is ignored by the device-entry search.
        let page = TestPageBuilder::new()
            .serial(4096, 5, 1016, b"hello")
            .build();
        assert!(page.find_device_entry(0).is_none());

        // Bad header magic: no entries are iterated at all.
        let page = TestPageBuilder::new()
            .device_mirror(DEV_OFFSET, DEV_MIN_SIZE, test_device_mirror(7))
            .build();
        unsafe { *page.region.as_ptr().cast::<u32>() = 0xDEAD_BEEF };
        assert!(page.find_device_entry(7).is_none());
    }

    #[test]
    fn test_find_device_entry_selects_by_uid() {
        // Multiple valid device entries with distinct uids; the lookup matches
        // by the uid carried in the TOC entry and returns the right entry.
        let page = TestPageBuilder::new()
            .device_mirror(DEV_OFFSET, DEV_MIN_SIZE, test_device_mirror(98))
            .device_mirror(DEV_OFFSET * 2, DEV_MIN_SIZE, test_device_mirror(99))
            .build();
        let e98 = page.find_device_entry(98).expect("uid 98 found");
        let uid98 = e98.mirror.device_uid;
        assert_eq!(uid98, 98);
        let e99 = page.find_device_entry(99).expect("uid 99 found");
        let uid99 = e99.mirror.device_uid;
        assert_eq!(uid99, 99);
    }

    #[test]
    fn test_write_serial_since_skips_malformed_then_reads_valid() {
        // First entry has a wrapping size (u64::MAX) that must be rejected
        // without panicking; a later valid serial entry is still read.
        let page = TestPageBuilder::new()
            .toc_entry(NitroTocEntry {
                entry_type: TOC_TYPE_SERIAL,
                flags: 0,
                offset: 4096,
                size: u64::MAX,
                extra: TocExtra::default(),
            })
            .serial(16384, 5, 1016, b"hello")
            .build();
        let mut buf = Vec::new();
        let (new_idx, _) = page.write_serial_since(Wrapping(0), &mut buf).unwrap();
        assert_eq!(new_idx, Wrapping(5));
        assert_eq!(&buf, b"hello");
    }

    #[test]
    fn test_write_serial_since_rejects_zero_and_oversized_capacity() {
        // The hypervisor publishes a valid ring before NE_START_ENCLAVE
        // returns, so either of these means it is broken: fail, don't drain.
        let page = TestPageBuilder::new().serial(4096, 5, 0, b"").build();
        let mut buf = Vec::new();
        let err = page.write_serial_since(Wrapping(0), &mut buf).unwrap_err();
        assert!(matches!(
            err,
            SerialRingError::BadCapacity { capacity: 0, .. }
        ));
        assert!(!err.is_retriable());

        // Capacity larger than the region's data area. Craft a TOC entry whose
        // recorded size is smaller than the ring's declared capacity.
        let page = TestPageBuilder::new()
            .toc_entry(NitroTocEntry {
                entry_type: TOC_TYPE_SERIAL,
                flags: 0,
                offset: 4096,
                size: 1024,
                extra: TocExtra::default(),
            })
            .build();
        let ring_base = unsafe { page.region.as_ptr().add(4096) };
        unsafe {
            ptr::write(ring_base.cast::<u32>(), 10);
            ptr::write(ring_base.add(4).cast::<u32>(), 4096);
        }
        let err = page.write_serial_since(Wrapping(0), &mut buf).unwrap_err();
        assert!(matches!(err, SerialRingError::BadCapacity { .. }));
        assert!(buf.is_empty());
    }

    #[test]
    fn test_write_serial_since_no_ring_is_fatal() {
        // A page whose TOC has no serial entry at all.
        let page = TestPageBuilder::new().build();
        let mut buf = Vec::new();
        let err = page.write_serial_since(Wrapping(0), &mut buf).unwrap_err();
        assert!(matches!(err, SerialRingError::NoRing));
        assert!(!err.is_retriable());
    }
}

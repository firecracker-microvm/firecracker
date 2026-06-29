// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Nitro Enclave info page: header, TOC, and serial ring buffer reader.
//!
//! The info page is a 2 MiB-aligned shared memory region containing
//! a TOC with entries for serial ring buffers. The enclave VMM writes device
//! state here; the parent VMM polls it.

use std::io;
use std::mem::size_of;

use vm_memory::{ByteValued, Bytes, VolatileSlice, WriteVolatile};

use super::ne_ioctl::EnclaveFd;
use crate::logger::warn;
use crate::utils::u64_to_usize;

/// Info page magic number (`NISC` in little-endian).
pub const INFO_PAGE_MAGIC: u32 = 0x5343_494E;

/// Info page size (2 MiB).
pub const INFO_PAGE_SIZE: usize = 2 * 1024 * 1024;

/// Required alignment of the info page (2 MiB), as mandated by `NE_SET_INFO_PAGE`.
const INFO_PAGE_ALIGN: usize = 2 * 1024 * 1024;

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
    /// Number of bytes written (monotonically increasing).
    write_idx: u32,
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
    Alloc(io::Error),
    /// NE_SET_INFO_PAGE ioctl failed: {0}
    Register(io::Error),
    /// invalid info page header magic
    InvalidHeader,
}

// ---------------------------------------------------------------------------
// InfoPage -- allocation, registration, and serial ring reading
// ---------------------------------------------------------------------------

/// A 2 MiB-aligned info page shared with the enclave VMM.
#[derive(Debug)]
pub struct InfoPage {
    /// Pointer to the start of the mapped 2 MiB region.
    ptr: *mut u8,
}

// SAFETY: InfoPage is only accessed via VolatileSlice (volatile reads/writes),
// never through shared references to the underlying memory. Concurrent writes
// from the enclave VMM are observed safely through volatile operations.
unsafe impl Send for InfoPage {}
// SAFETY: See Send impl.
unsafe impl Sync for InfoPage {}

impl InfoPage {
    /// Allocate a 2 MiB info page via CMA (mmap on the NE device fd).
    ///
    /// PCIE mode requires physically contiguous memory from the NE driver's
    /// CMA pool. `NE_SET_INFO_PAGE` requires the userspace address to be
    /// 2 MiB-aligned ([`INFO_PAGE_ALIGN`]), so allocate with explicit alignment
    /// rather than relying on the default mmap granularity.
    pub fn new(ne_dev_fd: &super::ne_ioctl::NitroEnclavesDevFd) -> Result<Self, InfoPageError> {
        let (ptr, _aligned_size) = ne_dev_fd
            .allocate_cma_aligned(INFO_PAGE_SIZE, INFO_PAGE_ALIGN)
            .map_err(InfoPageError::Alloc)?;
        Ok(Self { ptr })
    }

    /// Allocate a 2 MiB-aligned info page for testing without a real NE device.
    #[cfg(test)]
    pub fn allocate_anonymous() -> Result<Self, InfoPageError> {
        // SAFETY: mmap with MAP_ANONYMOUS|MAP_HUGETLB returns a 2 MiB-aligned mapping.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                INFO_PAGE_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_HUGETLB | libc::MAP_POPULATE,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(InfoPageError::Alloc(io::Error::last_os_error()));
        }
        // SAFETY: ptr is valid for INFO_PAGE_SIZE bytes.
        unsafe { std::ptr::write_bytes(ptr.cast::<u8>(), 0, INFO_PAGE_SIZE) };
        Ok(Self {
            ptr: ptr.cast::<u8>(),
        })
    }

    /// Register this info page with the NE kernel driver.
    pub fn register(&self, enclave_fd: &EnclaveFd) -> Result<(), InfoPageError> {
        enclave_fd
            .set_info_page(self.ptr as u64, INFO_PAGE_SIZE as u64)
            .map_err(InfoPageError::Register)
    }

    /// Get the userspace address of the info page.
    #[cfg(test)]
    pub fn addr(&self) -> usize {
        self.ptr as usize
    }

    /// Returns `true` if the info page header has valid magic.
    #[cfg(test)]
    pub fn header_valid(&self) -> bool {
        self.header().is_some()
    }

    /// Write new serial data since `last_write_idx` directly into `dst`.
    ///
    /// Returns the current `write_idx` if there is new data,
    /// or `None` if there is no serial ring buffer or no new data.
    pub fn write_serial_since<W: WriteVolatile>(
        &self,
        last_write_idx: u32,
        dst: &mut W,
    ) -> Option<u32> {
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
            // TODO(enclave): handle write_idx wrapping past u32::MAX (unlikely in
            // practice — ~4 GiB of serial output would be needed).
            let ring: SerialRingHeader = match vs.read_obj(offset) {
                Ok(r) => r,
                Err(e) => {
                    warn!("info page TOC entry {i}: serial ring read failed: {e}");
                    continue;
                }
            };
            let data_offset = offset + size_of::<SerialRingHeader>();
            if ring.capacity == 0
                || ring.write_idx <= last_write_idx
                || ring.capacity as usize > size - size_of::<SerialRingHeader>()
            {
                return None;
            }
            let new_bytes = ring.write_idx - last_write_idx;
            let read_len = new_bytes.min(ring.capacity);
            let start_pos = last_write_idx % ring.capacity;
            // `start_pos < capacity` and `read_len <= capacity <= INFO_PAGE_SIZE`,
            // so the sum cannot overflow u32.
            if start_pos + read_len <= ring.capacity {
                vs.write_all_volatile_to(data_offset + start_pos as usize, dst, read_len as usize)
                    .ok()?;
            } else {
                let first_chunk = ring.capacity - start_pos;
                vs.write_all_volatile_to(
                    data_offset + start_pos as usize,
                    dst,
                    first_chunk as usize,
                )
                .ok()?;
                vs.write_all_volatile_to(data_offset, dst, (read_len - first_chunk) as usize)
                    .ok()?;
            }
            return Some(ring.write_idx);
        }
        None
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

    fn as_volatile_slice(&self) -> VolatileSlice<'_> {
        // SAFETY: ptr is valid for INFO_PAGE_SIZE bytes, and the info page
        // lifetime is tied to &self.
        unsafe { VolatileSlice::new(self.ptr, INFO_PAGE_SIZE) }
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
    pub(crate) fn from_raw_ptr(ptr: *mut u8) -> Self {
        Self { ptr }
    }
}

impl Drop for InfoPage {
    fn drop(&mut self) {
        // SAFETY: ptr was returned by mmap with INFO_PAGE_SIZE.
        unsafe {
            libc::munmap(self.ptr.cast::<libc::c_void>(), INFO_PAGE_SIZE);
        }
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

    use std::ptr;

    use super::*;

    // A device region placed well clear of the serial region at offset 4096.
    const DEV_OFFSET: u32 = 8192;
    // Minimum TOC size find_device_entry accepts for a device entry.
    const DEV_MIN_SIZE: u64 = DEVICE_ENTRY_MIN_SIZE;

    // 1024 bytes total serial region minus 8-byte ring header (write_idx + capacity fields).
    const TEST_RING_CAPACITY: u32 = 1016;

    fn mmap_page() -> *mut libc::c_void {
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
        ptr
    }

    #[test]
    fn test_header_valid() {
        let ptr = mmap_page();
        let page = InfoPage {
            ptr: ptr.cast::<u8>(),
        };
        assert!(!page.header_valid());

        unsafe { *ptr.cast::<u32>() = INFO_PAGE_MAGIC };
        assert!(page.header_valid());
    }

    #[test]
    fn test_addr() {
        let ptr = mmap_page();
        let page = InfoPage {
            ptr: ptr.cast::<u8>(),
        };
        assert_eq!(page.addr(), ptr as usize);
    }

    #[test]
    fn test_read_serial_since() {
        // Basic read from offset 0.
        let page = make_test_page(5, TEST_RING_CAPACITY, b"hello");
        let mut buf = Vec::new();
        let new_idx = page.write_serial_since(0, &mut buf).unwrap();
        assert_eq!(new_idx, 5);
        assert_eq!(&buf, b"hello");

        // Incremental read from offset 5.
        let page = make_test_page(10, TEST_RING_CAPACITY, b"helloworld");
        buf.clear();
        let new_idx = page.write_serial_since(5, &mut buf).unwrap();
        assert_eq!(new_idx, 10);
        assert_eq!(&buf, b"world");

        // No new data when already caught up.
        let page = make_test_page(5, TEST_RING_CAPACITY, b"hello");
        buf.clear();
        assert!(page.write_serial_since(5, &mut buf).is_none());
    }

    #[test]
    fn test_serial_ring_buffer_wrap_around() {
        // write_idx (20) > capacity (16): reader should get at most `capacity` bytes.
        let page = make_test_page(20, 16, b"ABCDEFGHIJKLMNOP");
        let mut buf = Vec::new();
        let new_idx = page.write_serial_since(0, &mut buf).unwrap();
        assert_eq!(new_idx, 20);
        assert_eq!(buf.len(), 16);
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
        unsafe { *page.ptr.cast::<u32>() = 0xDEAD_BEEF };
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
        let new_idx = page.write_serial_since(0, &mut buf).unwrap();
        assert_eq!(new_idx, 5);
        assert_eq!(&buf, b"hello");
    }

    #[test]
    fn test_write_serial_since_rejects_zero_and_oversized_capacity() {
        // capacity == 0 -> None.
        let page = TestPageBuilder::new().serial(4096, 5, 0, b"").build();
        let mut buf = Vec::new();
        assert!(page.write_serial_since(0, &mut buf).is_none());

        // capacity larger than the region's data area -> None. Craft a TOC entry
        // whose recorded size is smaller than the ring's declared capacity.
        let page = TestPageBuilder::new()
            .toc_entry(NitroTocEntry {
                entry_type: TOC_TYPE_SERIAL,
                flags: 0,
                offset: 4096,
                size: 1024,
                extra: TocExtra::default(),
            })
            .build();
        let ring_base = unsafe { page.ptr.add(4096) };
        unsafe {
            ptr::write(ring_base.cast::<u32>(), 10);
            ptr::write(ring_base.add(4).cast::<u32>(), 4096);
        }
        assert!(page.write_serial_since(0, &mut buf).is_none());
    }
}

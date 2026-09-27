// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Safe wrappers over the subset of the Linux VFIO userspace API
//! (`include/uapi/linux/vfio.h`) needed to assign a PCI device through the type1 IOMMU backend.
//!
//! Design notes:
//!
//! * Every kernel call reports the exact kernel error. In particular `VFIO_DEVICE_SET_IRQS` returns
//!   a *positive* count when the kernel could only allocate part of the requested MSI/MSI-X vectors
//!   (`drivers/vfio/pci/vfio_pci_intrs.c: vfio_msi_enable`); this is reported as
//!   [`SetIrqsError::Partial`] rather than being mistaken for success.
//! * Nothing here issues ioctls or touches sysfs on drop. Closing the file descriptors is enough for
//!   the kernel to release everything in the right order: a device file holds a reference on its
//!   group file (`drivers/vfio/group.c: vfio_group_fops_release`), a group holds a reference on its
//!   container, and the type1 backend drops every DMA mapping when the container goes away.

use std::fs::{File, OpenOptions};
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::FileExt;

use vmm_sys_util::errno;
use vmm_sys_util::ioctl::{
    ioctl, ioctl_with_mut_ptr, ioctl_with_ptr, ioctl_with_ref, ioctl_with_val,
};
use vmm_sys_util::ioctl_io_nr;

use super::generated::vfio::_bindgen_ty_1::VFIO_PCI_CONFIG_REGION_INDEX;
use super::generated::vfio::_bindgen_ty_2::VFIO_PCI_MSIX_IRQ_INDEX;
use super::generated::vfio::{
    VFIO_API_VERSION, VFIO_BASE, VFIO_DEVICE_FLAGS_PCI, VFIO_DEVICE_FLAGS_RESET,
    VFIO_DMA_MAP_FLAG_READ, VFIO_DMA_MAP_FLAG_WRITE, VFIO_GROUP_FLAGS_CONTAINER_SET,
    VFIO_GROUP_FLAGS_VIABLE, VFIO_IOMMU_INFO_CAPS, VFIO_IOMMU_TYPE1_INFO_CAP_IOVA_RANGE,
    VFIO_IOMMU_TYPE1_INFO_DMA_AVAIL, VFIO_IRQ_SET_ACTION_TRIGGER, VFIO_IRQ_SET_ACTION_UNMASK,
    VFIO_IRQ_SET_DATA_EVENTFD, VFIO_IRQ_SET_DATA_NONE, VFIO_REGION_INFO_CAP_SPARSE_MMAP,
    VFIO_REGION_INFO_FLAG_CAPS, VFIO_REGION_INFO_FLAG_READ, VFIO_REGION_INFO_FLAG_WRITE, VFIO_TYPE,
    VFIO_TYPE1v2_IOMMU, vfio_device_info, vfio_group_status, vfio_info_cap_header,
    vfio_iommu_type1_dma_map, vfio_iommu_type1_info, vfio_iommu_type1_info_cap_iova_range,
    vfio_iommu_type1_info_dma_avail, vfio_iova_range, vfio_irq_info, vfio_irq_set,
    vfio_pci_dependent_device, vfio_pci_hot_reset, vfio_pci_hot_reset_info, vfio_region_info,
    vfio_region_info_cap_sparse_mmap, vfio_region_sparse_mmap_area,
};

// All VFIO requests are `_IO(VFIO_TYPE, VFIO_BASE + n)` (include/uapi/linux/vfio.h).
ioctl_io_nr!(VFIO_GET_API_VERSION, u32::from(VFIO_TYPE), VFIO_BASE);
ioctl_io_nr!(VFIO_CHECK_EXTENSION, u32::from(VFIO_TYPE), VFIO_BASE + 1);
ioctl_io_nr!(VFIO_SET_IOMMU, u32::from(VFIO_TYPE), VFIO_BASE + 2);
ioctl_io_nr!(VFIO_GROUP_GET_STATUS, u32::from(VFIO_TYPE), VFIO_BASE + 3);
ioctl_io_nr!(
    VFIO_GROUP_SET_CONTAINER,
    u32::from(VFIO_TYPE),
    VFIO_BASE + 4
);
ioctl_io_nr!(
    VFIO_GROUP_GET_DEVICE_FD,
    u32::from(VFIO_TYPE),
    VFIO_BASE + 6
);
ioctl_io_nr!(VFIO_DEVICE_GET_INFO, u32::from(VFIO_TYPE), VFIO_BASE + 7);
ioctl_io_nr!(
    VFIO_DEVICE_GET_REGION_INFO,
    u32::from(VFIO_TYPE),
    VFIO_BASE + 8
);
ioctl_io_nr!(
    VFIO_DEVICE_GET_IRQ_INFO,
    u32::from(VFIO_TYPE),
    VFIO_BASE + 9
);
ioctl_io_nr!(VFIO_DEVICE_SET_IRQS, u32::from(VFIO_TYPE), VFIO_BASE + 10);
ioctl_io_nr!(
    VFIO_DEVICE_GET_PCI_HOT_RESET_INFO,
    u32::from(VFIO_TYPE),
    VFIO_BASE + 12
);
ioctl_io_nr!(
    VFIO_DEVICE_PCI_HOT_RESET,
    u32::from(VFIO_TYPE),
    VFIO_BASE + 13
);
ioctl_io_nr!(VFIO_IOMMU_GET_INFO, u32::from(VFIO_TYPE), VFIO_BASE + 12);
ioctl_io_nr!(VFIO_IOMMU_MAP_DMA, u32::from(VFIO_TYPE), VFIO_BASE + 13);

/// Path of the VFIO container character device.
const VFIO_CONTAINER_PATH: &str = "/dev/vfio/vfio";

/// Errors returned by the VFIO wrappers.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum VfioSysError {
    /// Failed to open {0}: {1}
    Open(String, #[source] std::io::Error),
    /// {0} failed: {1}
    Ioctl(&'static str, #[source] errno::Error),
    /// Unsupported VFIO API version {0}
    ApiVersion(i32),
    /// The host kernel does not provide the VFIO type1v2 IOMMU backend
    NoType1v2Iommu,
    /// IOMMU group {0} is not viable: every device in the group must be bound to vfio-pci (or to no driver)
    GroupNotViable(u32),
    /// IOMMU group {0} is already attached to another VFIO container
    GroupInUse(u32),
    /// The VFIO device is not a PCI device
    NotPci,
    /// The VFIO device does not expose the PCI configuration space region
    NoConfigRegion,
    /// The VFIO device does not expose the MSI and MSI-X interrupt indexes
    NoMsiIrqIndexes,
    /// The kernel returned malformed {0} information
    MalformedInfo(&'static str),
    /// Access of {len} bytes at offset {offset:#x} is outside VFIO region {index}
    OutOfRange {
        /// VFIO region index.
        index: u32,
        /// Offset of the access in the region.
        offset: u64,
        /// Length of the access.
        len: usize,
    },
    /// VFIO region {0} does not allow this access
    AccessDenied(u32),
    /// Access to VFIO region {0} failed: {1}
    RegionAccess(u32, #[source] std::io::Error),
}

/// Error returned by [`Device::set_irq_eventfds`].
#[derive(Debug, PartialEq, Eq, thiserror::Error, displaydoc::Display)]
pub enum SetIrqsError {
    /// The host could only allocate {0} interrupt vectors
    Partial(u32),
    /// VFIO_DEVICE_SET_IRQS failed: {0}
    Ioctl(errno::Error),
}

/// Plain-old-data structures of the VFIO ABI.
///
/// # Safety
///
/// Implementors must be `#[repr(C)]`, have no padding bytes, be valid for every bit pattern and
/// have an alignment of at most 8 bytes. The VFIO UAPI structures satisfy this by design: they
/// only contain fixed-size integers laid out with explicit padding fields.
unsafe trait VfioAbi: Default {}

// SAFETY: integers are valid for every bit pattern and have no padding.
unsafe impl VfioAbi for u32 {}
// SAFETY: integers are valid for every bit pattern and have no padding.
unsafe impl VfioAbi for u64 {}
// SAFETY: `#[repr(C)]` struct of `u16`, `u16`, `u32`: no padding, any bit pattern is valid.
unsafe impl VfioAbi for vfio_info_cap_header {}
// SAFETY: `#[repr(C)]` struct of integers without padding (`pad` is explicit).
unsafe impl VfioAbi for vfio_iommu_type1_info {}
// SAFETY: `#[repr(C)]` struct of two `u64`.
unsafe impl VfioAbi for vfio_iova_range {}
// SAFETY: `#[repr(C)]` struct of a capability header and a `u32`: no padding.
unsafe impl VfioAbi for vfio_iommu_type1_info_dma_avail {}
// SAFETY: `#[repr(C)]` struct of `u32` and `u64` fields laid out without padding.
unsafe impl VfioAbi for vfio_region_info {}
// SAFETY: `#[repr(C)]` struct of two `u64`.
unsafe impl VfioAbi for vfio_region_sparse_mmap_area {}
// SAFETY: `#[repr(C)]` struct of five `u32` followed by a zero-sized flexible array.
unsafe impl VfioAbi for vfio_irq_set {}
// SAFETY: `#[repr(C)]` struct of three `u32` followed by a zero-sized flexible array.
unsafe impl VfioAbi for vfio_pci_hot_reset_info {}
// SAFETY: `#[repr(C)]` struct of a `u32` union, a `u16` and two `u8`: no padding, any bit
// pattern is valid for every variant.
unsafe impl VfioAbi for vfio_pci_dependent_device {}
// SAFETY: `#[repr(C)]` struct of three `u32` followed by a zero-sized flexible array.
unsafe impl VfioAbi for vfio_pci_hot_reset {}

/// A buffer of 8-byte aligned storage used for variable-sized VFIO ioctl arguments.
struct IoctlBuffer {
    storage: Vec<u64>,
    len: usize,
}

impl IoctlBuffer {
    fn new(len: usize) -> Self {
        Self {
            storage: vec![0u64; len.div_ceil(size_of::<u64>())],
            len,
        }
    }

    fn bytes(&self) -> &[u8] {
        // SAFETY: `storage` owns at least `len` initialized bytes.
        unsafe { std::slice::from_raw_parts(self.storage.as_ptr().cast::<u8>(), self.len) }
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: `storage` owns at least `len` initialized bytes and is borrowed mutably.
        unsafe { std::slice::from_raw_parts_mut(self.storage.as_mut_ptr().cast::<u8>(), self.len) }
    }

    /// Copy `value` to the start of the buffer.
    fn write_header<T: VfioAbi>(&mut self, value: &T) {
        assert!(size_of::<T>() <= self.len);
        // SAFETY: `T` has no padding (`VfioAbi`), so all its `size_of::<T>()` bytes are
        // initialized.
        let src = unsafe {
            std::slice::from_raw_parts(std::ptr::from_ref(value).cast::<u8>(), size_of::<T>())
        };
        self.bytes_mut()[..size_of::<T>()].copy_from_slice(src);
    }

    /// Read a `T` from byte offset `offset`, or `None` if it does not fit.
    fn read_at<T: VfioAbi>(&self, offset: usize) -> Option<T> {
        let end = offset.checked_add(size_of::<T>())?;
        let src = self.bytes().get(offset..end)?;
        let mut value = T::default();
        // SAFETY: `T` is valid for every bit pattern (`VfioAbi`) and `src` holds exactly
        // `size_of::<T>()` bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(
                src.as_ptr(),
                std::ptr::from_mut(&mut value).cast::<u8>(),
                size_of::<T>(),
            );
        }
        Some(value)
    }

    fn as_mut_ptr<T>(&mut self) -> *mut T {
        self.storage.as_mut_ptr().cast::<T>()
    }

    fn as_ptr<T>(&self) -> *const T {
        self.storage.as_ptr().cast::<T>()
    }
}

/// Walk a VFIO capability chain, returning `(id, version, byte offset)` for every capability.
///
/// `first` is the offset of the first capability header in `buf` (0 means no capability). The walk
/// is bounded by the buffer size, so a malformed chain cannot loop forever.
fn capability_chain(buf: &IoctlBuffer, first: u32) -> Result<Vec<(u16, u16, usize)>, VfioSysError> {
    let mut caps = Vec::new();
    let mut offset = first as usize;
    // Each header is at least `size_of::<vfio_info_cap_header>()` bytes, which bounds the number
    // of distinct capabilities that fit in the buffer.
    let max_caps = buf.len / size_of::<vfio_info_cap_header>();
    while offset != 0 {
        if caps.len() >= max_caps {
            return Err(VfioSysError::MalformedInfo("capability chain"));
        }
        let header: vfio_info_cap_header = buf
            .read_at(offset)
            .ok_or(VfioSysError::MalformedInfo("capability chain"))?;
        caps.push((header.id, header.version, offset));
        offset = header.next as usize;
    }
    Ok(caps)
}

fn u32_size_of<T>() -> u32 {
    u32::try_from(size_of::<T>()).expect("VFIO structures are smaller than 4 GiB")
}

/// A VFIO container: an IOMMU address space shared by every group attached to it.
#[derive(Debug)]
pub struct Container {
    file: File,
}

/// IOMMU properties of a container, as reported by `VFIO_IOMMU_GET_INFO`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IommuInfo {
    /// Inclusive `(start, end)` IOVA ranges usable for DMA mappings. Empty if the kernel does not
    /// report the capability (kernels before v5.4), in which case the whole IOVA space is usable.
    pub iova_ranges: Vec<(u64, u64)>,
    /// Number of DMA mappings that can still be created, if reported by the kernel (v5.10+).
    pub dma_avail: Option<u32>,
}

impl Container {
    /// Open `/dev/vfio/vfio` and check that the kernel provides the type1v2 IOMMU backend.
    pub fn open() -> Result<Self, VfioSysError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(VFIO_CONTAINER_PATH)
            .map_err(|err| VfioSysError::Open(VFIO_CONTAINER_PATH.to_string(), err))?;
        let container = Container { file };

        // SAFETY: `container` wraps a VFIO container fd and the request takes no argument.
        let version = unsafe { ioctl(&container, VFIO_GET_API_VERSION()) };
        if u32::try_from(version) != Ok(VFIO_API_VERSION) {
            return Err(VfioSysError::ApiVersion(version));
        }

        // SAFETY: `container` wraps a VFIO container fd and the argument is an extension id.
        let ret = unsafe {
            ioctl_with_val(
                &container,
                VFIO_CHECK_EXTENSION(),
                libc::c_ulong::from(VFIO_TYPE1v2_IOMMU),
            )
        };
        if ret != 1 {
            return Err(VfioSysError::NoType1v2Iommu);
        }

        Ok(container)
    }

    /// Select the type1v2 IOMMU backend. At least one group must be attached to the container,
    /// and every attached group is bound to the IOMMU domain by this call.
    pub fn set_iommu_type1v2(&self) -> Result<(), VfioSysError> {
        // SAFETY: `self` wraps a VFIO container fd and the argument is an IOMMU type.
        let ret = unsafe {
            ioctl_with_val(
                self,
                VFIO_SET_IOMMU(),
                libc::c_ulong::from(VFIO_TYPE1v2_IOMMU),
            )
        };
        if ret < 0 {
            return Err(VfioSysError::Ioctl("VFIO_SET_IOMMU", errno::Error::last()));
        }
        Ok(())
    }

    /// Query the IOMMU properties of the container (`VFIO_IOMMU_GET_INFO`).
    pub fn iommu_info(&self) -> Result<IommuInfo, VfioSysError> {
        let mut argsz = u32_size_of::<vfio_iommu_type1_info>();
        loop {
            let mut buf = IoctlBuffer::new(argsz as usize);
            buf.write_header(&vfio_iommu_type1_info {
                argsz,
                ..Default::default()
            });
            // SAFETY: `buf` holds `argsz` bytes starting with a `vfio_iommu_type1_info` header,
            // which is what the kernel reads and fills in.
            let ret = unsafe {
                ioctl_with_mut_ptr(
                    self,
                    VFIO_IOMMU_GET_INFO(),
                    buf.as_mut_ptr::<vfio_iommu_type1_info>(),
                )
            };
            if ret < 0 {
                return Err(VfioSysError::Ioctl(
                    "VFIO_IOMMU_GET_INFO",
                    errno::Error::last(),
                ));
            }
            let info: vfio_iommu_type1_info =
                buf.read_at(0).ok_or(VfioSysError::MalformedInfo("IOMMU"))?;
            if info.argsz > argsz {
                // The capability chain does not fit: retry with the size the kernel asked for.
                argsz = info.argsz;
                continue;
            }

            let mut result = IommuInfo {
                iova_ranges: Vec::new(),
                dma_avail: None,
            };
            if info.flags & VFIO_IOMMU_INFO_CAPS == 0 {
                return Ok(result);
            }
            for (id, _version, offset) in capability_chain(&buf, info.cap_offset)? {
                match u32::from(id) {
                    VFIO_IOMMU_TYPE1_INFO_CAP_IOVA_RANGE => {
                        let nr_iovas: u32 = buf
                            .read_at(
                                offset
                                    + std::mem::offset_of!(
                                        vfio_iommu_type1_info_cap_iova_range,
                                        nr_iovas
                                    ),
                            )
                            .ok_or(VfioSysError::MalformedInfo("IOVA range"))?;
                        let first = offset + size_of::<vfio_iommu_type1_info_cap_iova_range>();
                        for i in 0..nr_iovas as usize {
                            let range: vfio_iova_range = buf
                                .read_at(first + i * size_of::<vfio_iova_range>())
                                .ok_or(VfioSysError::MalformedInfo("IOVA range"))?;
                            result.iova_ranges.push((range.start, range.end));
                        }
                    }
                    VFIO_IOMMU_TYPE1_INFO_DMA_AVAIL => {
                        let cap: vfio_iommu_type1_info_dma_avail = buf
                            .read_at(offset)
                            .ok_or(VfioSysError::MalformedInfo("DMA availability"))?;
                        result.dma_avail = Some(cap.avail);
                    }
                    _ => {}
                }
            }
            return Ok(result);
        }
    }

    /// Map `size` bytes of this process' memory at `vaddr` to I/O virtual address `iova`, readable
    /// and writable by the devices attached to the container.
    ///
    /// # Safety
    ///
    /// `[vaddr, vaddr + size)` must be a valid mapping of this process that stays mapped for as
    /// long as the container exists, and no Rust reference to that memory may be held while the
    /// device can access it through DMA.
    pub unsafe fn map_dma(&self, iova: u64, size: u64, vaddr: u64) -> Result<(), VfioSysError> {
        let map = vfio_iommu_type1_dma_map {
            argsz: u32_size_of::<vfio_iommu_type1_dma_map>(),
            flags: VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE,
            vaddr,
            iova,
            size,
        };
        // SAFETY: `self` wraps a VFIO container fd and `map` is a valid `vfio_iommu_type1_dma_map`.
        // The caller guarantees the mapped memory outlives the mapping.
        let ret = unsafe { ioctl_with_ref(self, VFIO_IOMMU_MAP_DMA(), &map) };
        if ret < 0 {
            return Err(VfioSysError::Ioctl(
                "VFIO_IOMMU_MAP_DMA",
                errno::Error::last(),
            ));
        }
        Ok(())
    }
}

impl AsRawFd for Container {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

/// A VFIO group: the set of devices that share an IOMMU context on the host.
#[derive(Debug)]
pub struct Group {
    id: u32,
    file: File,
}

impl Group {
    /// Open `/dev/vfio/<id>` and check the group is viable and not yet used by a container.
    pub fn open(id: u32) -> Result<Self, VfioSysError> {
        let path = format!("/dev/vfio/{id}");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|err| VfioSysError::Open(path, err))?;
        let group = Group { id, file };

        let mut status = vfio_group_status {
            argsz: u32_size_of::<vfio_group_status>(),
            flags: 0,
        };
        // SAFETY: `group` wraps a VFIO group fd and `status` is a valid `vfio_group_status`.
        let ret = unsafe {
            ioctl_with_mut_ptr(
                &group,
                VFIO_GROUP_GET_STATUS(),
                std::ptr::from_mut(&mut status),
            )
        };
        if ret < 0 {
            return Err(VfioSysError::Ioctl(
                "VFIO_GROUP_GET_STATUS",
                errno::Error::last(),
            ));
        }
        if status.flags & VFIO_GROUP_FLAGS_VIABLE == 0 {
            return Err(VfioSysError::GroupNotViable(id));
        }
        if status.flags & VFIO_GROUP_FLAGS_CONTAINER_SET != 0 {
            return Err(VfioSysError::GroupInUse(id));
        }
        Ok(group)
    }

    /// The IOMMU group number.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Attach the group to `container`.
    pub fn set_container(&self, container: &Container) -> Result<(), VfioSysError> {
        let fd: RawFd = container.as_raw_fd();
        // SAFETY: `self` wraps a VFIO group fd and the argument points to a valid container fd.
        let ret = unsafe { ioctl_with_ref(self, VFIO_GROUP_SET_CONTAINER(), &fd) };
        if ret < 0 {
            return Err(VfioSysError::Ioctl(
                "VFIO_GROUP_SET_CONTAINER",
                errno::Error::last(),
            ));
        }
        Ok(())
    }

    /// Open the device named `name` (its PCI address, e.g. `0000:01:00.0`) in this group.
    pub fn open_device(&self, name: &str) -> Result<Device, VfioSysError> {
        let name = std::ffi::CString::new(name).map_err(|_| VfioSysError::NotPci)?;
        // SAFETY: `self` wraps a VFIO group fd and the argument is a NUL terminated string.
        let fd = unsafe { ioctl_with_ptr(self, VFIO_GROUP_GET_DEVICE_FD(), name.as_ptr()) };
        if fd < 0 {
            return Err(VfioSysError::Ioctl(
                "VFIO_GROUP_GET_DEVICE_FD",
                errno::Error::last(),
            ));
        }
        // SAFETY: the kernel returned a new file descriptor that we now exclusively own.
        let file = unsafe { File::from_raw_fd(fd) };
        Device::new(file)
    }
}

impl AsRawFd for Group {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

/// A VFIO region (a BAR, the expansion ROM or the configuration space) of a device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionInfo {
    /// `VFIO_REGION_INFO_FLAG_*` flags.
    pub flags: u32,
    /// Size of the region in bytes.
    pub size: u64,
    /// Offset of the region in the device file.
    pub offset: u64,
    /// The `(offset, size)` areas of the region that may be `mmap`ed, relative to the region
    /// start. `None` means the whole region may be mapped (subject to the mmap flag).
    pub sparse_mmap_areas: Option<Vec<(u64, u64)>>,
}

/// A VFIO interrupt index (INTx, MSI or MSI-X) of a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IrqInfo {
    /// `VFIO_IRQ_INFO_*` flags.
    pub flags: u32,
    /// Number of interrupts of this index.
    pub count: u32,
}

/// A device affected by a PCI hot (bus or slot) reset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HotResetDependency {
    /// IOMMU group of the device.
    pub group_id: u32,
    /// PCI segment of the device.
    pub segment: u16,
    /// PCI bus of the device.
    pub bus: u8,
    /// PCI device/function of the device.
    pub devfn: u8,
}

/// An open VFIO device.
#[derive(Debug)]
pub struct Device {
    file: File,
    flags: u32,
    regions: Vec<RegionInfo>,
    irqs: Vec<IrqInfo>,
}

impl Device {
    fn new(file: File) -> Result<Self, VfioSysError> {
        let mut info = vfio_device_info {
            argsz: u32_size_of::<vfio_device_info>(),
            ..Default::default()
        };
        // SAFETY: `file` is a VFIO device fd and `info` is a valid `vfio_device_info`.
        let ret = unsafe {
            ioctl_with_mut_ptr(&file, VFIO_DEVICE_GET_INFO(), std::ptr::from_mut(&mut info))
        };
        if ret < 0 {
            return Err(VfioSysError::Ioctl(
                "VFIO_DEVICE_GET_INFO",
                errno::Error::last(),
            ));
        }
        if info.flags & VFIO_DEVICE_FLAGS_PCI == 0 {
            return Err(VfioSysError::NotPci);
        }
        if info.num_regions <= VFIO_PCI_CONFIG_REGION_INDEX {
            return Err(VfioSysError::NoConfigRegion);
        }
        if info.num_irqs <= VFIO_PCI_MSIX_IRQ_INDEX {
            return Err(VfioSysError::NoMsiIrqIndexes);
        }

        // Only the indexes Firecracker uses are queried: the BAR, expansion ROM and configuration
        // space regions, and the INTx, MSI and MSI-X interrupts. vfio-pci implements them for every
        // device (a BAR or ROM the device does not have has size 0). The other indexes only exist
        // on some devices, and querying them fails with EINVAL on the others: the VGA region on
        // VGA devices with CONFIG_VFIO_PCI_VGA, the error interrupt on PCI Express devices.
        let regions = (0..=VFIO_PCI_CONFIG_REGION_INDEX)
            .map(|index| Self::query_region(&file, index))
            .collect::<Result<Vec<_>, _>>()?;
        let irqs = (0..=VFIO_PCI_MSIX_IRQ_INDEX)
            .map(|index| Self::query_irq(&file, index))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Device {
            file,
            flags: info.flags,
            regions,
            irqs,
        })
    }

    fn query_region(file: &File, index: u32) -> Result<RegionInfo, VfioSysError> {
        let mut argsz = u32_size_of::<vfio_region_info>();
        loop {
            let mut buf = IoctlBuffer::new(argsz as usize);
            buf.write_header(&vfio_region_info {
                argsz,
                index,
                ..Default::default()
            });
            // SAFETY: `file` is a VFIO device fd and `buf` holds `argsz` bytes starting with a
            // `vfio_region_info` header.
            let ret = unsafe {
                ioctl_with_mut_ptr(
                    file,
                    VFIO_DEVICE_GET_REGION_INFO(),
                    buf.as_mut_ptr::<vfio_region_info>(),
                )
            };
            if ret < 0 {
                return Err(VfioSysError::Ioctl(
                    "VFIO_DEVICE_GET_REGION_INFO",
                    errno::Error::last(),
                ));
            }
            let info: vfio_region_info = buf
                .read_at(0)
                .ok_or(VfioSysError::MalformedInfo("region"))?;
            if info.argsz > argsz {
                argsz = info.argsz;
                continue;
            }

            let mut sparse_mmap_areas = None;
            if info.flags & VFIO_REGION_INFO_FLAG_CAPS != 0 {
                for (id, _version, offset) in capability_chain(&buf, info.cap_offset)? {
                    if u32::from(id) != VFIO_REGION_INFO_CAP_SPARSE_MMAP {
                        continue;
                    }
                    let nr_areas: u32 = buf
                        .read_at(
                            offset
                                + std::mem::offset_of!(vfio_region_info_cap_sparse_mmap, nr_areas),
                        )
                        .ok_or(VfioSysError::MalformedInfo("sparse mmap"))?;
                    let first = offset + size_of::<vfio_region_info_cap_sparse_mmap>();
                    let areas = (0..nr_areas as usize)
                        .map(|i| {
                            buf.read_at::<vfio_region_sparse_mmap_area>(
                                first + i * size_of::<vfio_region_sparse_mmap_area>(),
                            )
                            .map(|area| (area.offset, area.size))
                            .ok_or(VfioSysError::MalformedInfo("sparse mmap"))
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    sparse_mmap_areas = Some(areas);
                }
            }

            return Ok(RegionInfo {
                flags: info.flags,
                size: info.size,
                offset: info.offset,
                sparse_mmap_areas,
            });
        }
    }

    fn query_irq(file: &File, index: u32) -> Result<IrqInfo, VfioSysError> {
        let mut info = vfio_irq_info {
            argsz: u32_size_of::<vfio_irq_info>(),
            index,
            ..Default::default()
        };
        // SAFETY: `file` is a VFIO device fd and `info` is a valid `vfio_irq_info`.
        let ret = unsafe {
            ioctl_with_mut_ptr(
                file,
                VFIO_DEVICE_GET_IRQ_INFO(),
                std::ptr::from_mut(&mut info),
            )
        };
        if ret < 0 {
            return Err(VfioSysError::Ioctl(
                "VFIO_DEVICE_GET_IRQ_INFO",
                errno::Error::last(),
            ));
        }
        Ok(IrqInfo {
            flags: info.flags,
            count: info.count,
        })
    }

    /// Whether the kernel can reset this device on its own (function, PM or slot/bus reset
    /// scoped to this device), i.e. whether it was reset when it was opened.
    pub fn supports_reset(&self) -> bool {
        self.flags & VFIO_DEVICE_FLAGS_RESET != 0
    }

    /// Information about region `index`, one of the BAR, expansion ROM and configuration space
    /// regions.
    pub fn region(&self, index: u32) -> Option<&RegionInfo> {
        self.regions.get(index as usize)
    }

    /// Information about interrupt index `index`, one of the INTx, MSI and MSI-X interrupts.
    pub fn irq(&self, index: u32) -> Option<IrqInfo> {
        self.irqs.get(index as usize).copied()
    }

    fn region_file_offset(
        &self,
        index: u32,
        offset: u64,
        len: usize,
        required_flag: u32,
    ) -> Result<u64, VfioSysError> {
        let region = self
            .region(index)
            .ok_or(VfioSysError::OutOfRange { index, offset, len })?;
        let end = offset.checked_add(len as u64);
        if end.is_none_or(|end| end > region.size) {
            return Err(VfioSysError::OutOfRange { index, offset, len });
        }
        if region.flags & required_flag == 0 {
            return Err(VfioSysError::AccessDenied(index));
        }
        Ok(region.offset + offset)
    }

    /// Read `data.len()` bytes at `offset` of region `index`.
    pub fn read_region(
        &self,
        index: u32,
        offset: u64,
        data: &mut [u8],
    ) -> Result<(), VfioSysError> {
        let file_offset =
            self.region_file_offset(index, offset, data.len(), VFIO_REGION_INFO_FLAG_READ)?;
        self.file
            .read_exact_at(data, file_offset)
            .map_err(|err| VfioSysError::RegionAccess(index, err))
    }

    /// Write `data` at `offset` of region `index`.
    pub fn write_region(&self, index: u32, offset: u64, data: &[u8]) -> Result<(), VfioSysError> {
        let file_offset =
            self.region_file_offset(index, offset, data.len(), VFIO_REGION_INFO_FLAG_WRITE)?;
        self.file
            .write_all_at(data, file_offset)
            .map_err(|err| VfioSysError::RegionAccess(index, err))
    }

    /// Route interrupts `start..start + fds.len()` of index `index` to the given eventfds,
    /// enabling the index if it is not enabled yet (`VFIO_IRQ_SET_DATA_EVENTFD |
    /// VFIO_IRQ_SET_ACTION_TRIGGER`). A fd of -1 leaves the corresponding interrupt unassigned.
    pub fn set_irq_eventfds(
        &self,
        index: u32,
        start: u32,
        fds: &[RawFd],
    ) -> Result<(), SetIrqsError> {
        let count = u32::try_from(fds.len()).expect("interrupt count fits in u32");
        let argsz = size_of::<vfio_irq_set>() + std::mem::size_of_val(fds);
        let mut buf = IoctlBuffer::new(argsz);
        buf.write_header(&vfio_irq_set {
            argsz: u32::try_from(argsz).expect("interrupt set size fits in u32"),
            flags: VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER,
            index,
            start,
            count,
            ..Default::default()
        });
        for (i, fd) in fds.iter().enumerate() {
            let at = size_of::<vfio_irq_set>() + i * size_of::<RawFd>();
            buf.bytes_mut()[at..at + size_of::<RawFd>()].copy_from_slice(&fd.to_ne_bytes());
        }
        // SAFETY: `self` wraps a VFIO device fd and `buf` holds a `vfio_irq_set` header followed
        // by `count` 32-bit file descriptors, as `argsz` says.
        let ret =
            unsafe { ioctl_with_ptr(self, VFIO_DEVICE_SET_IRQS(), buf.as_ptr::<vfio_irq_set>()) };
        match ret {
            0 => Ok(()),
            // `vfio_msi_enable` returns the number of vectors it could allocate when it could not
            // allocate all of them, and leaves the index disabled.
            n if n > 0 => Err(SetIrqsError::Partial(n.unsigned_abs())),
            _ => Err(SetIrqsError::Ioctl(errno::Error::last())),
        }
    }

    /// Unmask the (single) interrupt of index `index` whenever `fd` is signalled
    /// (`VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_UNMASK`). vfio-pci only accepts it for an
    /// enabled INTx, which it masks on the host each time it fires.
    pub fn set_irq_unmask_eventfd(&self, index: u32, fd: RawFd) -> Result<(), VfioSysError> {
        let argsz = size_of::<vfio_irq_set>() + size_of::<RawFd>();
        let mut buf = IoctlBuffer::new(argsz);
        buf.write_header(&vfio_irq_set {
            argsz: u32::try_from(argsz).expect("interrupt set size fits in u32"),
            flags: VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_UNMASK,
            index,
            start: 0,
            count: 1,
            ..Default::default()
        });
        let at = size_of::<vfio_irq_set>();
        buf.bytes_mut()[at..at + size_of::<RawFd>()].copy_from_slice(&fd.to_ne_bytes());
        // SAFETY: `self` wraps a VFIO device fd and `buf` holds a `vfio_irq_set` header followed
        // by one 32-bit file descriptor, as `argsz` says.
        let ret =
            unsafe { ioctl_with_ptr(self, VFIO_DEVICE_SET_IRQS(), buf.as_ptr::<vfio_irq_set>()) };
        if ret < 0 {
            return Err(VfioSysError::Ioctl(
                "VFIO_DEVICE_SET_IRQS",
                errno::Error::last(),
            ));
        }
        Ok(())
    }

    /// Disable every interrupt of index `index` (`VFIO_IRQ_SET_DATA_NONE |
    /// VFIO_IRQ_SET_ACTION_TRIGGER` with a count of 0).
    pub fn disable_irqs(&self, index: u32) -> Result<(), VfioSysError> {
        let set = vfio_irq_set {
            argsz: u32_size_of::<vfio_irq_set>(),
            flags: VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_ACTION_TRIGGER,
            index,
            start: 0,
            count: 0,
            ..Default::default()
        };
        // SAFETY: `self` wraps a VFIO device fd and `set` is a valid `vfio_irq_set` without data.
        let ret = unsafe { ioctl_with_ref(self, VFIO_DEVICE_SET_IRQS(), &set) };
        if ret < 0 {
            return Err(VfioSysError::Ioctl(
                "VFIO_DEVICE_SET_IRQS",
                errno::Error::last(),
            ));
        }
        Ok(())
    }

    /// List the devices a PCI hot reset of this device would affect.
    pub fn pci_hot_reset_info(&self) -> Result<Vec<HotResetDependency>, VfioSysError> {
        let mut argsz = u32_size_of::<vfio_pci_hot_reset_info>();
        loop {
            let mut buf = IoctlBuffer::new(argsz as usize);
            buf.write_header(&vfio_pci_hot_reset_info {
                argsz,
                ..Default::default()
            });
            // SAFETY: `self` wraps a VFIO device fd and `buf` holds `argsz` bytes starting with a
            // `vfio_pci_hot_reset_info` header.
            let ret = unsafe {
                ioctl_with_mut_ptr(
                    self,
                    VFIO_DEVICE_GET_PCI_HOT_RESET_INFO(),
                    buf.as_mut_ptr::<vfio_pci_hot_reset_info>(),
                )
            };
            let info: vfio_pci_hot_reset_info = buf
                .read_at(0)
                .ok_or(VfioSysError::MalformedInfo("hot reset"))?;
            if ret < 0 {
                let err = errno::Error::last();
                // ENOSPC means the array was too small; `count` holds the required size.
                if err.errno() == libc::ENOSPC {
                    let needed = size_of::<vfio_pci_hot_reset_info>()
                        + info.count as usize * size_of::<vfio_pci_dependent_device>();
                    let needed = u32::try_from(needed)
                        .map_err(|_| VfioSysError::MalformedInfo("hot reset"))?;
                    if needed <= argsz {
                        return Err(VfioSysError::MalformedInfo("hot reset"));
                    }
                    argsz = needed;
                    continue;
                }
                return Err(VfioSysError::Ioctl(
                    "VFIO_DEVICE_GET_PCI_HOT_RESET_INFO",
                    err,
                ));
            }
            return (0..info.count as usize)
                .map(|i| {
                    buf.read_at::<vfio_pci_dependent_device>(
                        size_of::<vfio_pci_hot_reset_info>()
                            + i * size_of::<vfio_pci_dependent_device>(),
                    )
                    .map(|dep| HotResetDependency {
                        // SAFETY: the group variant is the one the kernel fills for devices
                        // opened through a group (the only mode used here).
                        group_id: unsafe { dep.__bindgen_anon_1.group_id },
                        segment: dep.segment,
                        bus: dep.bus,
                        devfn: dep.devfn,
                    })
                    .ok_or(VfioSysError::MalformedInfo("hot reset"))
                })
                .collect();
        }
    }

    /// Perform a PCI hot (slot or bus) reset of this device. `groups` must contain every group
    /// listed by [`Device::pci_hot_reset_info`].
    pub fn pci_hot_reset(&self, groups: &[&Group]) -> Result<(), VfioSysError> {
        let argsz = size_of::<vfio_pci_hot_reset>() + groups.len() * size_of::<i32>();
        let mut buf = IoctlBuffer::new(argsz);
        buf.write_header(&vfio_pci_hot_reset {
            argsz: u32::try_from(argsz).expect("hot reset size fits in u32"),
            flags: 0,
            count: u32::try_from(groups.len()).expect("group count fits in u32"),
            ..Default::default()
        });
        for (i, group) in groups.iter().enumerate() {
            let at = size_of::<vfio_pci_hot_reset>() + i * size_of::<i32>();
            buf.bytes_mut()[at..at + size_of::<i32>()]
                .copy_from_slice(&group.as_raw_fd().to_ne_bytes());
        }
        // SAFETY: `self` wraps a VFIO device fd and `buf` holds a `vfio_pci_hot_reset` header
        // followed by `count` group fds, as `argsz` says.
        let ret = unsafe {
            ioctl_with_ptr(
                self,
                VFIO_DEVICE_PCI_HOT_RESET(),
                buf.as_ptr::<vfio_pci_hot_reset>(),
            )
        };
        if ret < 0 {
            return Err(VfioSysError::Ioctl(
                "VFIO_DEVICE_PCI_HOT_RESET",
                errno::Error::last(),
            ));
        }
        Ok(())
    }
}

impl AsRawFd for Device {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ioctl_numbers() {
        // The request codes are `_IO(';', 100 + n)`; these are the values listed in the seccomp
        // filters.
        assert_eq!(VFIO_GET_API_VERSION(), 15204);
        assert_eq!(VFIO_CHECK_EXTENSION(), 15205);
        assert_eq!(VFIO_SET_IOMMU(), 15206);
        assert_eq!(VFIO_GROUP_GET_STATUS(), 15207);
        assert_eq!(VFIO_GROUP_SET_CONTAINER(), 15208);
        assert_eq!(VFIO_GROUP_GET_DEVICE_FD(), 15210);
        assert_eq!(VFIO_DEVICE_GET_INFO(), 15211);
        assert_eq!(VFIO_DEVICE_GET_REGION_INFO(), 15212);
        assert_eq!(VFIO_DEVICE_GET_IRQ_INFO(), 15213);
        assert_eq!(VFIO_DEVICE_SET_IRQS(), 15214);
        assert_eq!(VFIO_DEVICE_GET_PCI_HOT_RESET_INFO(), 15216);
        assert_eq!(VFIO_DEVICE_PCI_HOT_RESET(), 15217);
        assert_eq!(VFIO_IOMMU_GET_INFO(), 15216);
        assert_eq!(VFIO_IOMMU_MAP_DMA(), 15217);
    }

    fn buffer_from_words(words: &[u64]) -> IoctlBuffer {
        let mut buf = IoctlBuffer::new(words.len() * 8);
        buf.storage.copy_from_slice(words);
        buf
    }

    #[test]
    fn test_capability_chain() {
        // Two capabilities at offsets 8 and 24. Header layout: id (u16), version (u16), next (u32).
        let cap = |id: u64, version: u64, next: u64| id | (version << 16) | (next << 32);
        let buf = buffer_from_words(&[0, cap(1, 1, 24), 0, cap(3, 2, 0), 0]);
        assert_eq!(
            capability_chain(&buf, 8).unwrap(),
            vec![(1, 1, 8), (3, 2, 24)]
        );
        assert_eq!(capability_chain(&buf, 0).unwrap(), vec![]);

        // A self loop is rejected instead of spinning forever.
        let looped = buffer_from_words(&[0, cap(1, 1, 8)]);
        assert!(matches!(
            capability_chain(&looped, 8),
            Err(VfioSysError::MalformedInfo(_))
        ));

        // A header running past the buffer is rejected.
        let truncated = buffer_from_words(&[0, cap(1, 1, 12)]);
        assert!(matches!(
            capability_chain(&truncated, 8),
            Err(VfioSysError::MalformedInfo(_))
        ));
    }

    #[test]
    fn test_ioctl_buffer() {
        let mut buf = IoctlBuffer::new(12);
        assert_eq!(buf.bytes().len(), 12);
        buf.write_header(&0x1122_3344_5566_7788u64);
        assert_eq!(buf.read_at::<u64>(0), Some(0x1122_3344_5566_7788));
        assert_eq!(buf.read_at::<u32>(8), Some(0));
        assert_eq!(buf.read_at::<u64>(8), None);
        assert_eq!(buf.read_at::<u32>(usize::MAX), None);
    }
}

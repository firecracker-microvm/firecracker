// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! VFIO based PCIe device passthrough.
//!
//! The Linux VFIO framework (<https://docs.kernel.org/driver-api/vfio.html>) exposes a physical
//! PCI device to userspace behind the IOMMU, which is what is needed to assign a host device (for
//! example a GPU) to a Firecracker microVM. This module provides:
//!
//! * [`sys`]: safe wrappers over the VFIO ioctls, built on bindings generated from the kernel UAPI
//!   headers ([`generated`]).
//! * [`VfioContext`]: the per-microVM IOMMU context. All assigned devices share one VFIO container
//!   (one IOMMU address space holding the guest memory mappings) and one KVM-VFIO pseudo device,
//!   which is how the kernel expects them to be used: KVM allows a single KVM-VFIO device per VM,
//!   and a group can only be opened once, so functions that share an IOMMU group must share a
//!   container.
//! * [`pci::VfioPciDevice`]: the emulation that turns an assigned function into a device on the
//!   guest's PCI bus.

pub mod generated;
mod interrupts;
pub mod pci;
pub mod sys;

use std::collections::BTreeMap;
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};

use kvm_bindings::{
    KVM_DEV_VFIO_FILE, KVM_DEV_VFIO_FILE_ADD, kvm_create_device, kvm_device_attr,
    kvm_device_type_KVM_DEV_TYPE_VFIO,
};
use kvm_ioctls::DeviceFd;
use vm_memory::{Address, GuestMemoryBackend, GuestMemoryRegion};

use crate::logger::{info, warn};
use crate::vstate::memory::GuestRegionType;
use crate::vstate::vm::KvmVm;
use sys::{Container, Device, Group, IommuInfo, VfioSysError};

/// Errors that can occur while setting up VFIO passthrough.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum VfioError {
    /// Invalid VFIO device path {0:?}: expected the sysfs directory of a PCI function
    InvalidPath(PathBuf),
    /// Cannot determine the IOMMU group of {0:?}: {1}
    IommuGroup(PathBuf, #[source] std::io::Error),
    /// The IOMMU group of {0:?} is not a number
    InvalidIommuGroup(PathBuf),
    /// PCI function {0} is assigned more than once
    DuplicateDevice(String),
    /// Failed to create the KVM VFIO pseudo device: {0}
    CreateKvmDevice(#[source] kvm_ioctls::Error),
    /// Failed to register IOMMU group {0} with KVM: {1}
    KvmAddGroup(u32, #[source] kvm_ioctls::Error),
    /// VFIO error for IOMMU group {0}: {1}
    Group(u32, #[source] VfioSysError),
    /// VFIO error for PCI function {0}: {1}
    Device(String, #[source] VfioSysError),
    /// VFIO container error: {0}
    Container(#[source] VfioSysError),
    /// Guest memory [{0:#x}, {1:#x}] is outside the I/O virtual address ranges the host IOMMU allows for DMA ({2})
    IovaUnavailable(u64, u64, String),
    /// Mapping guest memory for DMA needs {0} IOMMU mappings but the host allows only {1} more
    DmaMappingLimit(usize, u32),
    /// Hotpluggable guest memory cannot be used together with VFIO devices
    HotpluggableMemory,
    /// Failed to map guest memory [{0:#x}, {1:#x}] for DMA: {2}
    DmaMap(u64, u64, #[source] VfioSysError),
}

/// A PCI function to assign, identified by its host sysfs directory.
#[derive(Debug)]
struct DeviceLocation {
    /// The PCI address, e.g. `0000:01:00.0`, which is also the VFIO device name.
    name: String,
    /// The IOMMU group of the function.
    group: u32,
}

impl DeviceLocation {
    fn from_sysfs(path: &Path) -> Result<Self, VfioError> {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| VfioError::InvalidPath(path.to_path_buf()))?
            .to_string();
        // `<sysfs>/iommu_group` links to `/sys/kernel/iommu_groups/<N>`
        // (Documentation/ABI/testing/sysfs-kernel-iommu_groups).
        let link = std::fs::read_link(path.join("iommu_group"))
            .map_err(|err| VfioError::IommuGroup(path.to_path_buf(), err))?;
        let group = link
            .file_name()
            .and_then(|group| group.to_str())
            .and_then(|group| group.parse::<u32>().ok())
            .ok_or_else(|| VfioError::InvalidIommuGroup(path.to_path_buf()))?;
        Ok(DeviceLocation { name, group })
    }
}

/// An assigned PCI function, opened through VFIO.
#[derive(Debug)]
pub struct OpenedDevice {
    /// The PCI address of the function on the host, e.g. `0000:01:00.0`.
    pub name: String,
    /// The host sysfs path the function was requested with.
    pub sysfs_path: PathBuf,
    /// The VFIO device.
    pub device: Device,
}

/// The IOMMU context shared by every device assigned to one microVM.
#[derive(Debug)]
pub struct VfioContext {
    /// The KVM-VFIO pseudo device. It tells KVM which groups are assigned, which KVM needs to
    /// handle non-coherent DMA correctly (e.g. to honour guest `WBINVD`).
    _kvm_device: DeviceFd,
    /// The container: a single IOMMU address space holding the guest memory mappings.
    _container: Container,
    /// The groups attached to the container, by IOMMU group number.
    groups: BTreeMap<u32, Group>,
}

impl VfioContext {
    /// Assign the PCI functions located at `sysfs_paths` to the microVM owned by `vm`.
    ///
    /// Every group involved is attached to a single container coupled to KVM, all of guest memory
    /// is mapped for DMA, and devices the kernel could not reset when they were opened are reset
    /// through a PCI hot reset when that is possible. The opened devices are returned in the order
    /// of `sysfs_paths`.
    ///
    /// Each function must be bound to the `vfio-pci` driver on the host, and so must every other
    /// device in its IOMMU group (bridges excepted), otherwise the kernel reports the group as not
    /// viable.
    pub fn new(vm: &KvmVm, sysfs_paths: &[&Path]) -> Result<(Self, Vec<OpenedDevice>), VfioError> {
        let locations = sysfs_paths
            .iter()
            .map(|path| DeviceLocation::from_sysfs(path))
            .collect::<Result<Vec<_>, _>>()?;
        for (i, location) in locations.iter().enumerate() {
            if locations[..i]
                .iter()
                .any(|other| other.name == location.name)
            {
                return Err(VfioError::DuplicateDevice(location.name.clone()));
            }
        }

        let mut kvm_device_config = kvm_create_device {
            type_: kvm_device_type_KVM_DEV_TYPE_VFIO,
            fd: 0,
            flags: 0,
        };
        let kvm_device = vm
            .fd()
            .create_device(&mut kvm_device_config)
            .map_err(VfioError::CreateKvmDevice)?;

        let container = Container::open().map_err(VfioError::Container)?;

        // Attach every group before selecting the IOMMU backend, so that `VFIO_SET_IOMMU` binds
        // them all to the IOMMU domain at once and `VFIO_IOMMU_GET_INFO` reports the IOVA ranges
        // valid for all of them.
        let mut groups = BTreeMap::new();
        for location in &locations {
            if groups.contains_key(&location.group) {
                continue;
            }
            let group =
                Group::open(location.group).map_err(|err| VfioError::Group(location.group, err))?;
            group
                .set_container(&container)
                .map_err(|err| VfioError::Group(location.group, err))?;
            groups.insert(location.group, group);
        }
        container
            .set_iommu_type1v2()
            .map_err(VfioError::Container)?;

        Self::map_guest_memory(vm, &container)?;

        for group in groups.values() {
            let fd: RawFd = group.as_raw_fd();
            let attr = kvm_device_attr {
                flags: 0,
                group: KVM_DEV_VFIO_FILE,
                attr: u64::from(KVM_DEV_VFIO_FILE_ADD),
                addr: std::ptr::from_ref(&fd) as u64,
            };
            kvm_device
                .set_device_attr(&attr)
                .map_err(|err| VfioError::KvmAddGroup(group.id(), err))?;
        }

        let devices = locations
            .into_iter()
            .zip(sysfs_paths)
            .map(|(location, path)| {
                groups[&location.group]
                    .open_device(&location.name)
                    .map(|device| OpenedDevice {
                        name: location.name.clone(),
                        sysfs_path: path.to_path_buf(),
                        device,
                    })
                    .map_err(|err| VfioError::Device(location.name, err))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let context = VfioContext {
            _kvm_device: kvm_device,
            _container: container,
            groups,
        };
        context.reset_devices(&devices);

        Ok((context, devices))
    }

    /// Map all of guest memory into the container's IOMMU address space, with I/O virtual
    /// addresses equal to guest physical addresses.
    fn map_guest_memory(vm: &KvmVm, container: &Container) -> Result<(), VfioError> {
        let mut regions = Vec::new();
        for region in vm.guest_memory().iter() {
            if region.region_type != GuestRegionType::Dram {
                return Err(VfioError::HotpluggableMemory);
            }
            regions.push((
                region.start_addr().raw_value(),
                region.len(),
                region.as_ptr() as u64,
            ));
        }

        let iommu = container.iommu_info().map_err(VfioError::Container)?;
        validate_dma_layout(
            &regions
                .iter()
                .map(|&(start, len, _)| (start, len))
                .collect::<Vec<_>>(),
            &iommu,
        )?;

        for (start, len, host_addr) in regions {
            // SAFETY: guest DRAM is an anonymous (or memfd/hugetlbfs) mapping created before the
            // VM and never unmapped or moved while the VM exists; the container, and with it this
            // DMA mapping, is dropped together with the VM. Firecracker only accesses guest memory
            // through volatile accessors, never through Rust references, so concurrent device DMA
            // does not violate aliasing rules.
            unsafe { container.map_dma(start, len, host_addr) }
                .map_err(|err| VfioError::DmaMap(start, start + len - 1, err))?;
        }
        Ok(())
    }

    /// Reset the devices the kernel could not reset when they were opened.
    ///
    /// Opening a device makes vfio-pci reset it when the kernel has a reset method scoped to that
    /// function (`vfio_pci_core_enable`), which is what `VFIO_DEVICE_FLAGS_RESET` reports. For the
    /// other devices a slot or bus reset is the only option; the kernel only allows it when every
    /// device it affects belongs to a group owned by the caller. When that is not the case the
    /// device is assigned without reset, which is also what QEMU does.
    fn reset_devices(&self, devices: &[OpenedDevice]) {
        // Addresses (segment, bus, devfn) already reset through an earlier hot reset.
        let mut reset_done: Vec<(u16, u8, u8)> = Vec::new();
        for opened in devices {
            if opened.device.supports_reset() {
                continue;
            }
            let dependencies = match opened.device.pci_hot_reset_info() {
                Ok(dependencies) => dependencies,
                Err(err) => {
                    warn!(
                        "vfio: {} has no reset method and cannot be hot reset ({err}); assigning \
                         it without reset",
                        opened.name
                    );
                    continue;
                }
            };
            let addresses: Vec<_> = dependencies
                .iter()
                .map(|dep| (dep.segment, dep.bus, dep.devfn))
                .collect();
            if addresses.iter().all(|address| reset_done.contains(address)) {
                continue;
            }
            let mut groups: Vec<&Group> = Vec::new();
            let mut missing = None;
            for dep in &dependencies {
                match self.groups.get(&dep.group_id) {
                    Some(group) => {
                        if !groups.iter().any(|g| g.id() == group.id()) {
                            groups.push(group);
                        }
                    }
                    None => missing = Some(dep.group_id),
                }
            }
            if let Some(group) = missing {
                warn!(
                    "vfio: {} has no reset method and a hot reset would also reset devices in \
                     IOMMU group {group}, which is not assigned to this microVM; assigning it \
                     without reset",
                    opened.name
                );
                continue;
            }
            match opened.device.pci_hot_reset(&groups) {
                Ok(()) => {
                    info!("vfio: {} reset through a PCI hot reset", opened.name);
                    reset_done.extend(addresses);
                }
                Err(err) => warn!(
                    "vfio: PCI hot reset of {} failed ({err}); assigning it without reset",
                    opened.name
                ),
            }
        }
    }
}

/// Check that guest memory regions, given as `(start, len)`, can be mapped for DMA with I/O
/// virtual addresses equal to their guest physical addresses.
fn validate_dma_layout(regions: &[(u64, u64)], iommu: &IommuInfo) -> Result<(), VfioError> {
    for &(start, len) in regions {
        let end = start + len - 1;
        let covered = iommu.iova_ranges.is_empty()
            || iommu
                .iova_ranges
                .iter()
                .any(|&(range_start, range_end)| range_start <= start && end <= range_end);
        if !covered {
            let ranges = iommu
                .iova_ranges
                .iter()
                .map(|(s, e)| format!("[{s:#x}, {e:#x}]"))
                .collect::<Vec<_>>()
                .join(", ");
            return Err(VfioError::IovaUnavailable(start, end, ranges));
        }
    }
    if let Some(avail) = iommu.dma_avail
        && regions.len() > avail as usize
    {
        return Err(VfioError::DmaMappingLimit(regions.len(), avail));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_dma_layout() {
        // x86 IOMMUs reserve the MSI doorbell window at 0xfee00000.
        let iommu = IommuInfo {
            iova_ranges: vec![(0, 0xfedf_ffff), (0xfef0_0000, 0xff_ffff_ffff)],
            dma_avail: Some(65535),
        };
        validate_dma_layout(&[(0, 0xc000_0000), (1 << 32, 1 << 32)], &iommu).unwrap();

        // A region crossing the reserved window is rejected.
        assert!(matches!(
            validate_dma_layout(&[(0, 0xff00_0000)], &iommu),
            Err(VfioError::IovaUnavailable(0, 0xfeff_ffff, _))
        ));
        // A region reaching the end of the IOMMU aperture fits, one crossing it is rejected.
        validate_dma_layout(&[(0xff_0000_0000, 1 << 32)], &iommu).unwrap();
        assert!(matches!(
            validate_dma_layout(&[(0xff_8000_0000, 1 << 32)], &iommu),
            Err(VfioError::IovaUnavailable(..))
        ));

        // Kernels without the IOVA range capability allow any IOVA.
        let unrestricted = IommuInfo {
            iova_ranges: vec![],
            dma_avail: None,
        };
        validate_dma_layout(&[(0xff_0000_0000, 1 << 32)], &unrestricted).unwrap();

        // The number of mappings is bounded by the available DMA entries.
        let limited = IommuInfo {
            iova_ranges: vec![],
            dma_avail: Some(1),
        };
        assert!(matches!(
            validate_dma_layout(&[(0, 0x1000), (1 << 32, 0x1000)], &limited),
            Err(VfioError::DmaMappingLimit(2, 1))
        ));
    }

    #[test]
    fn test_device_location() {
        let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let device = dir.as_path().join("0000:01:00.0");
        std::fs::create_dir(&device).unwrap();

        // No iommu_group link: the device is not behind an IOMMU (or not a PCI function).
        assert!(matches!(
            DeviceLocation::from_sysfs(&device),
            Err(VfioError::IommuGroup(..))
        ));

        std::os::unix::fs::symlink(
            "../../../../kernel/iommu_groups/49",
            device.join("iommu_group"),
        )
        .unwrap();
        let location = DeviceLocation::from_sysfs(&device).unwrap();
        assert_eq!(location.name, "0000:01:00.0");
        assert_eq!(location.group, 49);

        let bad_device = dir.as_path().join("0000:02:00.0");
        std::fs::create_dir(&bad_device).unwrap();
        std::os::unix::fs::symlink("../iommu_groups/abc", bad_device.join("iommu_group")).unwrap();
        assert!(matches!(
            DeviceLocation::from_sysfs(&bad_device),
            Err(VfioError::InvalidIommuGroup(..))
        ));

        assert!(matches!(
            DeviceLocation::from_sysfs(Path::new("/")),
            Err(VfioError::InvalidPath(..))
        ));
    }
}

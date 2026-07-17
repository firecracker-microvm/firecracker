// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Nitro Enclaves VM lifecycle management.
//!
//! Wraps the NE kernel API to create, configure, and start an enclave.

use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Mutex};

use vm_memory::{
    Bytes, GuestAddress, GuestMemoryBackend, GuestMemoryError, GuestMemoryRegion,
    GuestRegionCollectionError,
};

use crate::logger::info;
use crate::nitro_enclave::cpu_accounting::AccountingThreads;
use crate::nitro_enclave::info_page::InfoPage;
use crate::nitro_enclave::ne_ioctl::{EnclaveFd, NitroEnclavesDevFd};
use crate::nitro_enclave::serial_console::ConsoleReader;
use crate::utils::u64_to_usize;
use crate::vstate::memory::{GuestMemoryMmap, GuestRegionMmapExt, MemoryError};

/// Errors from enclave VM operations.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum EnclaveVmError {
    /// Failed to create enclave VM: {0}
    CreateVm(std::io::Error),
    /// Failed to add vCPU {cpu_id}: {source}
    AddVcpu {
        /// vCPU ID that failed.
        cpu_id: u32,
        /// Underlying error.
        source: std::io::Error,
    },
    /// Failed to set user memory region: {0}
    SetMemoryRegion(std::io::Error),
    /// Failed to revoke parent access to donated enclave memory: {0}
    Mprotect(MemoryError),
    /// Failed to get image load info: {0}
    GetImageLoadInfo(std::io::Error),
    /// Failed to start enclave: {0}
    StartEnclave(std::io::Error),
    /// Image offset {offset} + image size {image_size} exceeds allocated memory {mem_size}
    ImageTooLarge {
        /// Offset from NE_GET_IMAGE_LOAD_INFO.
        offset: u64,
        /// EIF image size.
        image_size: u64,
        /// Total memory allocated.
        mem_size: u64,
    },
    /// Failed to allocate info page: {0}
    InfoPageAlloc(crate::nitro_enclave::info_page::InfoPageError),
    /// Failed to register info page: {0}
    InfoPageRegister(crate::nitro_enclave::info_page::InfoPageError),
    /// Failed to allocate CMA memory: {0}
    CmaAlloc(MemoryError),
    /// Failed to write the EIF image into guest memory: {0}
    WriteImage(GuestMemoryError),
    /// Failed to build guest memory mapping: {0}
    BuildGuestMemory(GuestRegionCollectionError),
}

/// The donated enclave RAM, retained for the `EnclaveVm`'s lifetime so its
/// owning regions stay mapped until teardown (dropping would `munmap` them).
#[derive(Debug)]
enum EnclaveRam {
    /// Direct mode: shared with the parent, used as device DMA memory.
    Direct(GuestMemoryMmap),
    /// Confidential mode: PROT_NONE after donation, isolated from the parent.
    /// Held only to keep the mapping reserved until drop; never accessed.
    Confidential {
        /// Retained for its `Drop` (unmaps the region); not read otherwise.
        _region: GuestMemoryMmap,
    },
}

/// Manages the lifecycle of a Nitro Enclave VM.
///
/// Provides methods to create the VM, add vCPUs, allocate CMA memory,
/// load the EIF image, and start the enclave.
pub struct EnclaveVm {
    /// CPU-accounting threads (Parent-PID visibility); `Some` only when the
    /// enclave was created with `NE_ENCLAVE_CPU_ACCOUNTING_MODE`. Declared
    /// before `enclave_fd` so field-order drop stops and joins the threads
    /// before the enclave fd closes.
    accounting_threads: Option<AccountingThreads>,
    /// NE device fd (`/dev/nitro_enclaves`).
    dev_fd: NitroEnclavesDevFd,
    /// Enclave instance fd from `NE_CREATE_VM2`.
    enclave_fd: EnclaveFd,
    /// Slot UID assigned by the hypervisor on `NE_CREATE_VM2`.
    slot_uid: u64,
    /// Whether the enclave was started with PCIE hotplug mode.
    hotplug_enabled: bool,
    /// DMB size in MiB for confidential mode; `None` in direct mode.
    dmb_size_mib: Option<u64>,
    /// Info page for PCIE topology mode.
    info_page: Option<Arc<InfoPage>>,
    /// Donated enclave RAM; `None` until `load_and_add_memory` runs.
    enclave_ram: Option<EnclaveRam>,
    /// Serial console reader (debug mode only), also polled by the event
    /// manager; kept here so [`Self::flush_console`] can drain it.
    console: Option<Arc<Mutex<ConsoleReader>>>,
}

impl std::fmt::Debug for EnclaveVm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnclaveVm")
            .field("info_page", &self.info_page.is_some())
            .field("enclave_ram", &self.enclave_ram.is_some())
            .finish()
    }
}

impl EnclaveVm {
    /*
     * Enclave guest physical address layout — stable NE ABI.
     *
     * These addresses are baked into the hypervisor's memory map and
     * cannot change without breaking every existing enclave image.
     *
     * The NE hypervisor maps RAM around a PCI MMIO hole at 0x8000_0000
     * on both architectures:
     *
     * x86_64:
     *   [0x0000_0000, 0x8000_0000)  low RAM  (up to 2 GiB)
     *   [0x8000_0000, 0x1_0000_0000) PCI MMIO hole (no RAM here)
     *   [0x1_0000_0000, ...)         high RAM (overflow)
     *
     * aarch64:
     *   [0x0000_0000, 0x4000_0000)  device MMIO (GIC, ECAM, ...)
     *   [0x4000_0000, 0x8000_0000)  low RAM  (up to 1 GiB)
     *   [0x8000_0000, 0x4_0000_0000) PCI MMIO hole (no RAM here)
     *   [0x4_0000_0000, ...)         high RAM (overflow)
     *
     * When the enclave has more RAM than fits in the low region, we
     * create two guest memory regions so GPA translation matches what
     * the hypervisor actually mapped.
     */

    /// Start of low enclave RAM.
    #[cfg(target_arch = "aarch64")]
    pub const ENCLAVE_RAM_BASE: u64 = 0x4000_0000;
    /// Start of low enclave RAM.
    #[cfg(target_arch = "x86_64")]
    pub const ENCLAVE_RAM_BASE: u64 = 0;

    /// Start of the 32-bit PCI MMIO window.
    const PCIE_MMIO_BASE: u64 = 0x8000_0000;

    /// Maximum low RAM size before the MMIO split is needed.
    #[allow(clippy::cast_possible_truncation)]
    const LOW_RAM_MAX_SIZE: usize = (Self::PCIE_MMIO_BASE - Self::ENCLAVE_RAM_BASE) as usize;

    /// Start of high RAM above the PCI MMIO window.
    #[cfg(target_arch = "aarch64")]
    const HIGH_RAM_BASE: u64 = 0x4_0000_0000;
    /// Start of high RAM above the PCI MMIO window.
    #[cfg(target_arch = "x86_64")]
    const HIGH_RAM_BASE: u64 = 0x1_0000_0000;

    /// Split `size` bytes of enclave RAM into `(gpa, size)` regions around the
    /// PCI MMIO hole: one below `LOW_RAM_MAX_SIZE`, and (if RAM exceeds that) a
    /// second at `HIGH_RAM_BASE` above the hole. Each region is donated as its
    /// own owning CMA region; the hypervisor concatenates them in donation order.
    fn split_ram_regions(size: usize) -> Vec<(GuestAddress, usize)> {
        if size > Self::LOW_RAM_MAX_SIZE {
            vec![
                (GuestAddress(Self::ENCLAVE_RAM_BASE), Self::LOW_RAM_MAX_SIZE),
                (
                    GuestAddress(Self::HIGH_RAM_BASE),
                    size - Self::LOW_RAM_MAX_SIZE,
                ),
            ]
        } else {
            vec![(GuestAddress(Self::ENCLAVE_RAM_BASE), size)]
        }
    }

    /// Create a new enclave VM from a pre-opened device fd, issuing
    /// `NE_CREATE_VM2` with `create_flags`.
    ///
    /// `create_flags` carries every NE_ENCLAVE_*_MODE bit EXCEPT DEBUG
    /// (DEBUG is per-launch and travels with NE_START_ENCLAVE). Callers
    /// typically open the device fd and call `get_supported_flags()` before
    /// this, so they can compose `create_flags` against what the hypervisor
    /// actually supports.
    pub fn new(
        dev_fd: NitroEnclavesDevFd,
        create_flags: u32,
        hotplug_enabled: bool,
        dmb_size_mib: Option<u64>,
    ) -> Result<Self, EnclaveVmError> {
        let (enclave_fd, slot_uid) = dev_fd
            .create_vm(create_flags)
            .map_err(EnclaveVmError::CreateVm)?;

        Ok(Self {
            accounting_threads: None,
            dev_fd,
            enclave_fd,
            slot_uid,
            hotplug_enabled,
            dmb_size_mib,
            info_page: None,
            enclave_ram: None,
            console: None,
        })
    }

    /// Slot UID assigned by the hypervisor.
    pub fn slot_uid(&self) -> u64 {
        self.slot_uid
    }

    /// Whether the enclave was started with PCIE hotplug mode.
    pub fn hotplug_enabled(&self) -> bool {
        self.hotplug_enabled
    }

    /// Per-device DMB size in MiB for confidential mode; `None` in direct mode.
    pub fn dmb_size_mib(&self) -> Option<u64> {
        self.dmb_size_mib
    }

    /// Retain the CPU-accounting threads so they are stopped and joined when
    /// the enclave VM is dropped.
    pub fn set_accounting_threads(&mut self, threads: AccountingThreads) {
        self.accounting_threads = Some(threads);
    }

    /// Add a specific vCPU to the enclave by CPU ID.
    pub fn add_vcpu(&mut self, cpu_id: u32) -> Result<(), EnclaveVmError> {
        self.enclave_fd
            .add_vcpu(cpu_id)
            .map_err(|e| EnclaveVmError::AddVcpu { cpu_id, source: e })?;
        Ok(())
    }

    /// Atomically pick and add a vCPU using NE_ADD_ANY_VCPU.
    ///
    /// The kernel picks an unused core (optionally biased to a NUMA node)
    /// under a lock, avoiding the TOCTOU race of NE_ADD_VCPU(0).
    pub fn add_any_vcpu(&mut self, numa_hint: i32) -> Result<(), EnclaveVmError> {
        self.enclave_fd
            .add_any_vcpu(numa_hint)
            .map_err(|e| EnclaveVmError::AddVcpu {
                cpu_id: 0,
                source: e,
            })?;
        Ok(())
    }

    /// Allocate CMA memory, copy the EIF image into it, then donate the
    /// memory to the NE driver.
    ///
    /// The EIF must be written into the CMA pages **before** calling
    /// `NE_SET_USER_MEMORY_REGION`, because that ioctl donates the pages
    /// to the enclave and userspace can no longer access them (in
    /// confidential mode).
    ///
    /// The donated memory is retained in both modes so its owning mapping stays
    /// reserved for the enclave's lifetime. Direct mode exposes it via
    /// [`Self::guest_memory`] as device DMA memory; confidential mode keeps it
    /// PROT_NONE and inaccessible to the parent.
    pub fn load_and_add_memory(
        &mut self,
        size: usize,
        eif_data: &[u8],
        direct_mode: bool,
    ) -> Result<(), EnclaveVmError> {
        let ram_regions = Self::split_ram_regions(size);

        // Verify the EIF fits in low RAM (guest node 0) before allocating any
        // CMA, so an oversized image fails cheaply.
        let load_info = self
            .enclave_fd
            .get_image_load_info()
            .map_err(EnclaveVmError::GetImageLoadInfo)?;
        let offset = u64_to_usize(load_info.memory_offset);
        let low_size = ram_regions[0].1;
        if offset + eif_data.len() > low_size {
            return Err(EnclaveVmError::ImageTooLarge {
                offset: offset as u64,
                image_size: eif_data.len() as u64,
                mem_size: low_size as u64,
            });
        }

        // Allocate one owning CMA region per RAM region and donate each.
        // Read-write: the EIF is written here before donation, and direct mode
        // keeps using the regions as device DMA memory afterwards.
        let regions = ram_regions
            .iter()
            .enumerate()
            .map(|(idx, &(gpa, region_size))| {
                let region = self
                    .dev_fd
                    .allocate_cma_region(gpa, region_size, libc::PROT_READ | libc::PROT_WRITE)
                    .map_err(EnclaveVmError::CmaAlloc)?;
                info!(
                    "CMA alloc: gpa={:#x} host={:#x} size={} MiB",
                    gpa.0,
                    region.as_ptr() as usize,
                    region.len() / (1024 * 1024),
                );
                Ok(GuestRegionMmapExt::dram_from_mmap_region(
                    region,
                    u32::try_from(idx).expect("region count fits in u32"),
                ))
            })
            .collect::<Result<Vec<_>, EnclaveVmError>>()?;

        let guest_mem =
            GuestMemoryMmap::from_regions(regions).map_err(EnclaveVmError::BuildGuestMemory)?;

        let dest = GuestAddress(Self::ENCLAVE_RAM_BASE + offset as u64);
        guest_mem
            .write_slice(eif_data, dest)
            .map_err(EnclaveVmError::WriteImage)?;

        // Donate each region separately; the hypervisor concatenates them into
        // its fixed GPA layout in donation order.
        for region in guest_mem.iter() {
            self.enclave_fd
                .set_user_memory_region(region.as_ptr() as u64, region.len())
                .map_err(EnclaveVmError::SetMemoryRegion)?;
        }

        self.enclave_ram = Some(if direct_mode {
            // Direct mode keeps the regions as the devices' DMA memory.
            EnclaveRam::Direct(guest_mem)
        } else {
            // Donation revoked the parent's access, so PROT_NONE each region to
            // match. The region is retained (not dropped): its owning mapping
            // must stay reserved for the enclave's lifetime, since dropping
            // would munmap and free the VA back to the parent.
            for region in guest_mem.iter() {
                for slot in region.plugged_slots() {
                    slot.protect(true).map_err(EnclaveVmError::Mprotect)?;
                }
            }
            EnclaveRam::Confidential { _region: guest_mem }
        });

        Ok(())
    }

    /// Start the enclave with explicit flags bitmask.
    ///
    /// Returns the assigned CID. `flags` is a bitmask of
    /// `start_flags::*` constants. `cid` is the requested CID
    /// (0 for auto-assign).
    pub fn start(&mut self, flags: u64, cid: u64) -> Result<u64, EnclaveVmError> {
        self.enclave_fd
            .start(flags, cid)
            .map_err(EnclaveVmError::StartEnclave)
    }

    /// Allocate and register the info page with the NE kernel driver.
    ///
    /// Uses CMA allocation (mmap on the NE device fd) for physically contiguous
    /// memory that the hypervisor can resolve.
    pub fn install_info_page(&mut self) -> Result<(), EnclaveVmError> {
        let page = InfoPage::new(&self.dev_fd).map_err(EnclaveVmError::InfoPageAlloc)?;
        page.register(&self.enclave_fd)
            .map_err(EnclaveVmError::InfoPageRegister)?;
        self.info_page = Some(Arc::new(page));
        Ok(())
    }

    /// Get the raw enclave fd for event polling (e.g., to detect HUP).
    pub fn enclave_raw_fd(&self) -> std::os::unix::io::RawFd {
        self.enclave_fd.as_raw_fd()
    }

    /// Get a reference to the enclave fd for issuing device ioctls.
    pub fn enclave_fd(&self) -> &EnclaveFd {
        &self.enclave_fd
    }

    /// Get a shared reference to the info page (available after `install_info_page`).
    pub fn info_page(&self) -> Option<Arc<InfoPage>> {
        self.info_page.clone()
    }

    /// Retain the serial console reader for [`Self::flush_console`].
    pub fn set_console(&mut self, console: Arc<Mutex<ConsoleReader>>) {
        self.console = Some(console);
    }

    /// Drain any pending serial output from the info-page ring, if a console
    /// reader is installed. No-op otherwise.
    pub fn flush_console(&self) {
        if let Some(console) = &self.console {
            console
                .lock()
                .expect("poisoned console lock")
                .flush_serial();
        }
    }

    /// Get a reference to the parent-accessible guest memory, if any.
    ///
    /// `Some` only in direct mode, where the donated enclave RAM stays mapped
    /// for the parent to use as device DMA memory. `None` in confidential mode:
    /// the enclave RAM is isolated after donation, and devices use per-device
    /// DMBs instead.
    pub fn guest_memory(&self) -> Option<&GuestMemoryMmap> {
        match &self.enclave_ram {
            Some(EnclaveRam::Direct(mem)) => Some(mem),
            Some(EnclaveRam::Confidential { .. }) | None => None,
        }
    }

    /// Allocate a Device Memory Buffer (DMB) for a confidential-mode device.
    ///
    /// The DMB is a CMA-backed region from the NE driver's pool, shared with the
    /// enclave so that virtqueue rings stay accessible to the parent while the
    /// rest of the enclave RAM is isolated. It is returned as a single-region
    /// `GuestMemoryMmap` at `GuestAddress(0)`; the region owns its CMA mapping
    /// and munmaps it on drop.
    pub fn create_dmb(&self, size_bytes: usize) -> Result<GuestMemoryMmap, EnclaveVmError> {
        // Read-write: the parent services queue rings in this DMA memory.
        let region = self
            .dev_fd
            .allocate_cma_region(
                GuestAddress(0),
                size_bytes,
                libc::PROT_READ | libc::PROT_WRITE,
            )
            .map_err(EnclaveVmError::CmaAlloc)?;
        GuestMemoryMmap::from_regions(vec![GuestRegionMmapExt::dram_from_mmap_region(region, 0)])
            .map_err(EnclaveVmError::BuildGuestMemory)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        // Span sizes below, at, and well above the MMIO hole so both the
        // single-region and split cases (incl. the boundary) are exercised.
        #[test]
        fn test_split_ram_regions(size in 1usize..=(EnclaveVm::LOW_RAM_MAX_SIZE * 2)) {
            let ram_regions = EnclaveVm::split_ram_regions(size);

            // The regions exactly cover `size`, low region first at the RAM base.
            let total: usize = ram_regions.iter().map(|&(_, s)| s).sum();
            prop_assert_eq!(total, size);
            prop_assert_eq!(ram_regions[0].0, GuestAddress(EnclaveVm::ENCLAVE_RAM_BASE));
            prop_assert!(ram_regions[0].1 <= EnclaveVm::LOW_RAM_MAX_SIZE);

            if size > EnclaveVm::LOW_RAM_MAX_SIZE {
                // Split around the hole: low region fills it, overflow lands high.
                prop_assert_eq!(ram_regions.len(), 2);
                prop_assert_eq!(ram_regions[0].1, EnclaveVm::LOW_RAM_MAX_SIZE);
                prop_assert_eq!(ram_regions[1].0, GuestAddress(EnclaveVm::HIGH_RAM_BASE));
            } else {
                prop_assert_eq!(ram_regions.len(), 1);
            }
        }
    }
}

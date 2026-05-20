// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Nitro Enclaves VM lifecycle management.
//!
//! Wraps the NE kernel API to create, configure, and start an enclave.

use std::os::unix::io::AsRawFd;
use std::sync::Arc;

use vm_memory::{Bytes, GuestAddress};

use crate::logger::info;
use crate::nitro_enclave::info_page::InfoPage;
use crate::nitro_enclave::ne_ioctl::{EnclaveFd, NitroEnclavesDevFd};
use crate::utils::u64_to_usize;
use crate::vstate::memory::{GuestMemoryMmap, GuestRegionMmap, GuestRegionMmapExt};

/// CMA alignment required by the NE hypervisor (2 MiB).
const ALIGN_2M: usize = 2 * 1024 * 1024;

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
    CmaAlloc(std::io::Error),
    /// Failed to build guest memory mapping: {0}
    BuildGuestMemory(String),
}

/// Manages the lifecycle of a Nitro Enclave VM.
///
/// Provides methods to create the VM, add vCPUs, allocate CMA memory,
/// load the EIF image, and start the enclave.
pub struct EnclaveVm {
    /// NE device fd (`/dev/nitro_enclaves`).
    dev_fd: NitroEnclavesDevFd,
    /// Enclave instance fd from `NE_CREATE_VM2`.
    enclave_fd: EnclaveFd,
    /// Slot UID assigned by the hypervisor on `NE_CREATE_VM2`.
    slot_uid: u64,
    /// Info page for PCIE topology mode.
    info_page: Option<Arc<InfoPage>>,
    /// Cached `GuestMemoryMmap` wrapping the CMA region.
    guest_memory: Option<GuestMemoryMmap>,
}

impl std::fmt::Debug for EnclaveVm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnclaveVm")
            .field("info_page", &self.info_page.is_some())
            .field("guest_memory", &self.guest_memory.is_some())
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

    /// Create a new enclave VM from a pre-opened device fd, issuing
    /// `NE_CREATE_VM2` with `create_flags`.
    ///
    /// `create_flags` carries every NE_ENCLAVE_*_MODE bit EXCEPT DEBUG
    /// (DEBUG is per-launch and travels with NE_START_ENCLAVE). Callers
    /// typically open the device fd and call `get_supported_flags()` before
    /// this, so they can compose `create_flags` against what the hypervisor
    /// actually supports.
    pub fn new(dev_fd: NitroEnclavesDevFd, create_flags: u32) -> Result<Self, EnclaveVmError> {
        let (enclave_fd, slot_uid) = dev_fd
            .create_vm(create_flags)
            .map_err(EnclaveVmError::CreateVm)?;

        Ok(Self {
            dev_fd,
            enclave_fd,
            slot_uid,
            info_page: None,
            guest_memory: None,
        })
    }

    /// Slot UID assigned by the hypervisor.
    pub fn slot_uid(&self) -> u64 {
        self.slot_uid
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
    pub fn load_and_add_memory(
        &mut self,
        size: usize,
        eif_data: &[u8],
    ) -> Result<(), EnclaveVmError> {
        let (mem_ptr, aligned_size) = self
            .dev_fd
            .allocate_cma_aligned(size, ALIGN_2M)
            .map_err(EnclaveVmError::CmaAlloc)?;
        let aligned_addr = mem_ptr as usize;

        info!(
            "CMA alloc: aligned={:#x} size={} MiB",
            aligned_addr,
            aligned_size / (1024 * 1024)
        );

        let load_info = self
            .enclave_fd
            .get_image_load_info()
            .map_err(EnclaveVmError::GetImageLoadInfo)?;
        let offset = u64_to_usize(load_info.memory_offset);

        if offset + eif_data.len() > aligned_size {
            return Err(EnclaveVmError::ImageTooLarge {
                offset: offset as u64,
                image_size: eif_data.len() as u64,
                mem_size: aligned_size as u64,
            });
        }

        let guest_mem = Self::build_guest_memory(mem_ptr, aligned_size)?;
        let dest = GuestAddress(Self::ENCLAVE_RAM_BASE + offset as u64);
        guest_mem
            .write_slice(eif_data, dest)
            .map_err(|e| EnclaveVmError::CmaAlloc(std::io::Error::other(e)))?;
        self.guest_memory = Some(guest_mem);

        self.enclave_fd
            .set_user_memory_region(aligned_addr as u64, aligned_size as u64)
            .map_err(EnclaveVmError::SetMemoryRegion)?;

        // Note: The GuestMemoryMmap wrapping this CMA region uses
        // `with_raw_mmap_pointer`, which sets owned=false — so its Drop
        // won't munmap. The NE driver takes ownership of the physical pages
        // after donation; the VA mapping is cleaned up on process exit.
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

    /// Get a reference to the guest memory, if available.
    pub fn guest_memory(&self) -> Option<&GuestMemoryMmap> {
        self.guest_memory.as_ref()
    }

    /// Wrap a (ptr, size, gpa) triple into a `GuestRegionMmapExt`.
    ///
    /// # Safety
    ///
    /// `ptr` must be valid for `size` bytes and must not be munmap'd for
    /// the lifetime of the returned region.
    unsafe fn make_guest_region(
        ptr: *mut u8,
        size: usize,
        gpa: GuestAddress,
        idx: u32,
    ) -> Result<GuestRegionMmapExt, EnclaveVmError> {
        // Wrap the externally-owned CMA mapping WITHOUT taking ownership: the NE
        // driver (donated RAM) or the caller (Dmb/InfoPage) owns the mapping and
        // unmaps it, so `from_raw_ptr` builds an owned=false region whose Drop
        // does not munmap.
        // SAFETY: caller guarantees ptr is valid for size bytes and stays mapped.
        let guest_region = unsafe {
            GuestRegionMmap::from_raw_ptr(
                ptr,
                size,
                gpa,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
            )
            .map_err(|e| EnclaveVmError::BuildGuestMemory(format!("{e}")))?
        };
        Ok(GuestRegionMmapExt::dram_from_mmap_region(guest_region, idx))
    }

    /// Build a `GuestMemoryMmap` wrapping a raw CMA pointer.
    ///
    /// The guest physical address must match where the NE hypervisor maps
    /// enclave RAM, so that virtio queue addresses from the enclave guest
    /// resolve correctly against this memory region.
    ///
    /// When RAM exceeds `LOW_RAM_MAX_SIZE`, splits it into two regions
    /// around the PCI MMIO hole (see layout comment above).
    pub(crate) fn build_guest_memory(
        mem_ptr: *mut u8,
        size: usize,
    ) -> Result<GuestMemoryMmap, EnclaveVmError> {
        let ram_base = GuestAddress(Self::ENCLAVE_RAM_BASE);
        let regions = if size > Self::LOW_RAM_MAX_SIZE {
            let low_size = Self::LOW_RAM_MAX_SIZE;
            let high_size = size - low_size;
            // SAFETY: mem_ptr is valid for `size` bytes (mmap'd in
            // load_and_add_memory, not munmap'd). ptr.add(low_size) is
            // within the same allocation since low_size < size.
            unsafe {
                vec![
                    Self::make_guest_region(mem_ptr, low_size, ram_base, 0)?,
                    Self::make_guest_region(
                        mem_ptr.add(low_size),
                        high_size,
                        GuestAddress(Self::HIGH_RAM_BASE),
                        1,
                    )?,
                ]
            }
        } else {
            // SAFETY: mem_ptr is valid for `size` bytes (see above).
            unsafe { vec![Self::make_guest_region(mem_ptr, size, ram_base, 0)?] }
        };

        GuestMemoryMmap::from_regions(regions)
            .map_err(|e| EnclaveVmError::BuildGuestMemory(format!("{e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use vm_memory::GuestMemoryBackend;

    fn alloc_test_memory(size: usize) -> *mut u8 {
        // SAFETY: MAP_ANONYMOUS mmap always returns a valid mapping on success.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        assert_ne!(ptr, libc::MAP_FAILED);
        ptr.cast::<u8>()
    }

    #[test]
    fn test_build_guest_memory_single_region() {
        let size = 512 * 1024 * 1024; // 512 MiB, below LOW_RAM_MAX_SIZE
        let ptr = alloc_test_memory(size);
        let mem = EnclaveVm::build_guest_memory(ptr, size).unwrap();
        assert_eq!(mem.num_regions(), 1);
    }

    #[test]
    fn test_build_guest_memory_split_regions() {
        let size = EnclaveVm::LOW_RAM_MAX_SIZE + 2 * 1024 * 1024;
        let ptr = alloc_test_memory(size);
        let mem = EnclaveVm::build_guest_memory(ptr, size).unwrap();
        assert_eq!(mem.num_regions(), 2);
    }
}

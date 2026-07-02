// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Device Memory Buffer (DMB) for confidential-mode enclave devices.
//!
//! In confidential mode the enclave's RAM is isolated from the parent VMM, so
//! a virtio device's virtqueue rings cannot live in guest RAM. Instead each
//! device gets a DMB: a CMA-backed region from the NE driver's pool that the
//! parent shares with the enclave (registered as a `VIRTIO_SHMEM_ID_DMB`
//! backing range in `NE_ADD_DEVICE`). The enclave guest, having negotiated
//! `VIRTIO_F_IOMMU_PLATFORM`, routes device DMA into this buffer, which the
//! parent can read and write to service the queues.
//!
//! There is one DMB per device, allocated when the device is attached and
//! owned for the device's lifetime.

use vm_memory::{GuestAddress, GuestMemoryBackend, GuestMemoryRegion, MemoryRegionAddress};

use crate::nitro_enclave::enclave_vm::{EnclaveVm, EnclaveVmError};
use crate::nitro_enclave::ne_ioctl::NitroEnclavesDevFd;
use crate::utils::u64_to_usize;
use crate::vstate::memory::{GuestMemoryMmap, GuestRegionMmapExt};

/// CMA alignment required by the NE driver (2 MiB).
const ALIGN_2M: usize = 2 * 1024 * 1024;

/// A per-device Device Memory Buffer backed by NE CMA memory.
///
/// The `GuestMemoryMmap` is the single source of truth for the mapping: the
/// host address and size handed to `NE_ADD_DEVICE` are derived from its region,
/// so they cannot drift from what the device actually sees.
#[derive(Debug)]
pub struct Dmb {
    /// The CMA region wrapped as guest memory at `GuestAddress(0)`. Single
    /// source of truth for the mapping's host address and size.
    memory: GuestMemoryMmap,
}

// SAFETY: The DMB owns its mapping exclusively and all access goes through
// `memory` (GuestMemoryMmap); the host pointer is only read to register the
// backing range with the NE driver and to munmap on drop.
unsafe impl Send for Dmb {}
// SAFETY: See Send impl.
unsafe impl Sync for Dmb {}

impl Dmb {
    /// Allocate a DMB of at least `size_bytes` from the NE driver's CMA pool.
    ///
    /// The allocation is rounded up to a 2 MiB boundary and wrapped as a single
    /// guest memory region at `GuestAddress(0)`.
    pub fn new(dev_fd: &NitroEnclavesDevFd, size_bytes: usize) -> Result<Self, EnclaveVmError> {
        // Read-write: the parent services queue rings in this DMA memory.
        let (ptr, aligned_size) = dev_fd
            .allocate_cma_aligned(size_bytes, ALIGN_2M, libc::PROT_READ | libc::PROT_WRITE)
            .map_err(EnclaveVmError::CmaAlloc)?;

        // SAFETY: `ptr` is valid for `aligned_size` bytes (just mmap'd) and is
        // owned by this `Dmb` for its lifetime (munmap only happens in Drop).
        // Wrapping the freshly-mmap'd region can only fail on a programming
        // error (bad builder args), never at runtime, so `expect` here rather
        // than threading an error path that would otherwise leak the mapping.
        let region = unsafe {
            EnclaveVm::make_guest_region(ptr, aligned_size, GuestAddress(0), 0)
                .expect("wrapping a freshly-mmap'd DMB region cannot fail")
        };
        let memory = GuestMemoryMmap::from_regions(vec![region])
            .expect("building guest memory from a single DMB region cannot fail");

        Ok(Self { memory })
    }

    /// The DMB region exposed as guest memory at `GuestAddress(0)`.
    pub fn guest_memory(&self) -> &GuestMemoryMmap {
        &self.memory
    }

    /// The single region backing the DMB.
    fn region(&self) -> &GuestRegionMmapExt {
        self.memory
            .find_region(GuestAddress(0))
            .expect("DMB always has a region at GuestAddress(0)")
    }

    /// Host userspace virtual address of the DMB, for `NE_ADD_DEVICE`.
    pub fn host_addr(&self) -> u64 {
        self.region()
            .get_host_address(MemoryRegionAddress(0))
            .expect("DMB region has a host address") as u64
    }

    /// Size of the DMB in bytes.
    pub fn size(&self) -> u64 {
        self.region().len()
    }
}

impl Drop for Dmb {
    fn drop(&mut self) {
        // The region wraps the CMA mapping with `with_raw_mmap_pointer`
        // (owned=false), so vm-memory will NOT munmap it on drop. The NE driver
        // cannot own a 2 MiB-aligned MAP_FIXED mapping through vm-memory's
        // MmapRegionBuilder (no alignment control, MAP_FIXED rejected), so — as
        // with `InfoPage` and `PmemMmap` — the DMB keeps the raw mapping and
        // frees it here. Unlike donated enclave RAM, the parent owns this
        // mapping for the device's lifetime and must release it.
        let addr = self.host_addr();
        let size = u64_to_usize(self.size());
        // SAFETY: `addr`/`size` describe the live CMA mapping created in `new`,
        // not yet unmapped (Dmb owns it exclusively).
        unsafe {
            libc::munmap(addr as *mut libc::c_void, size);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `Dmb` from anonymous memory for tests without a real NE device.
    fn anonymous_dmb(size: usize) -> Dmb {
        // SAFETY: MAP_ANONYMOUS mmap returns a valid mapping on success.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_SHARED,
                -1,
                0,
            )
        };
        assert_ne!(ptr, libc::MAP_FAILED);
        let ptr = ptr.cast::<u8>();
        // SAFETY: ptr is valid for `size` bytes and owned by the returned Dmb.
        let region =
            unsafe { EnclaveVm::make_guest_region(ptr, size, GuestAddress(0), 0).unwrap() };
        let memory = GuestMemoryMmap::from_regions(vec![region]).unwrap();
        Dmb { memory }
    }

    #[test]
    fn test_dmb_accessors() {
        let dmb = anonymous_dmb(ALIGN_2M);
        // host_addr and size are derived from the single backing region.
        assert_eq!(dmb.size(), ALIGN_2M as u64);
        assert_ne!(dmb.host_addr(), 0);

        // The memory exposes a single region at GuestAddress(0).
        let region = dmb.guest_memory().find_region(GuestAddress(0)).unwrap();
        assert_eq!(region.start_addr(), GuestAddress(0));
        assert_eq!(region.len(), ALIGN_2M as u64);
    }
}

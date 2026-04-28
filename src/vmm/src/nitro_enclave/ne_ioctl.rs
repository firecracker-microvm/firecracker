// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Nitro Enclaves kernel ioctl bindings.
//!
//! These structures and constants match the Nitro Enclaves kernel UAPI.

use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use vmm_sys_util::ioctl::{ioctl_with_mut_ref, ioctl_with_ref};
use vmm_sys_util::{ioctl_ior_nr, ioctl_iow_nr, ioctl_iowr_nr};

use crate::align_up;

/// Path to the Nitro Enclaves device node.
const NE_DEV_PATH: &str = "/dev/nitro_enclaves";

// NE ioctl magic number
const NE_MAGIC: std::os::raw::c_uint = 0xAE;

/// NE image load info flags
pub mod image_load_flags {
    /// Load image in enclave memory.
    pub const NE_EIF_IMAGE: u64 = 0x01;
}

/// NE enclave start flags.
pub mod start_flags {
    /// Start enclave in debug mode (unmatched, bit 0).
    pub const NE_ENCLAVE_DEBUG_MODE: u64 = 1 << 0;
    /// Start enclave in direct (non-confidential) mode (unmatched, bit 1).
    pub const NE_ENCLAVE_DIRECT_MODE: u64 = 1 << 1;
    /// Start enclave with the PCIe device model (matched, bit 6).
    pub const NE_ENCLAVE_PCIE_MODE: u64 = 1 << 6;
    /// Rigid Enclaves-1.5 shape: exactly one virtio-vsock (matched, bit 7).
    pub const NE_ENCLAVE_PCIE_VSOCK_MODE: u64 = 1 << 7;
    /// Allow NE_ADD_DEVICE after NE_START_ENCLAVE (matched, bit 8).
    pub const NE_ENCLAVE_PCIE_HOTPLUG_MODE: u64 = 1 << 8;
    /// Permissive virtio PCIe: any virtio subtype may be attached (matched, bit 9).
    pub const NE_ENCLAVE_PCIE_VIRTIO_MODE: u64 = 1 << 9;
    /// Mask of unmatched flags (low 6 bits).
    pub const NE_ENCLAVE_FLAG_UNMATCHED_MASK: u64 = 0x003F;
    /// Mask of matched flags (must equal EIF header matched bits at START).
    pub const NE_ENCLAVE_FLAG_MATCHED_MASK: u64 = 0xFFC0;
}

// ---------------------------------------------------------------------------
// Ioctl structures
// ---------------------------------------------------------------------------

/// Information about where to load the enclave image.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct NeImageLoadInfo {
    /// Flags for image loading (e.g., `NE_EIF_IMAGE`).
    pub flags: u64,
    /// Memory offset where the image should be loaded (output).
    pub memory_offset: u64,
}

/// Describes a user memory region to be added to the enclave.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct NeUserMemoryRegion {
    /// Flags (currently must be 0).
    pub flags: u64,
    /// Size of the memory region in bytes.
    pub memory_size: u64,
    /// Userspace address of the memory region.
    pub userspace_addr: u64,
}

/// Information for starting the enclave.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct NeEnclaveStartInfo {
    /// Flags (e.g., `NE_ENCLAVE_DEBUG_MODE`).
    pub flags: u64,
    /// Enclave CID (0 = auto-assign, filled in on return).
    pub enclave_cid: u64,
}

/// NE_CREATE_VM2 ioctl payload (`struct ne_create_vm_args` in the kernel UAPI).
///
/// `flags` carries every NE_ENCLAVE_*_MODE bit EXCEPT NE_ENCLAVE_DEBUG_MODE
/// (DEBUG is per-launch and travels with NE_START_ENCLAVE).
/// `padding` is reserved for future extension of `flags`; MUST be zero.
/// `slot_uid` is the output assigned by the hypervisor on success.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct NeCreateVmArgs {
    /// Input: launch-time flag word, every NE_ENCLAVE_*_MODE bit except DEBUG.
    pub flags: u32,
    /// Reserved for future extension of `flags`; the kernel rejects non-zero
    /// values.
    pub padding: u32,
    /// Output: unique slot id assigned by the hypervisor.
    pub slot_uid: u64,
}

/// Info page registration for PCIE topology mode.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct NeInfoPage {
    /// Userspace address of the info page (2 MiB aligned).
    pub userspace_addr: u64,
    /// Size of the info page region (must be 2 MiB).
    pub size: u64,
}

/// NE_ADD_ANY_VCPU ioctl payload. Atomically picks and adds a vCPU,
/// optionally biased toward a preferred host NUMA node.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct NeAddAnyVcpuArgs {
    /// Preferred host NUMA node, or [`NE_NUMA_ANY`] (-1) for no preference.
    pub numa_hint: i32,
}

/// No NUMA preference — pick from any node.
pub const NE_NUMA_ANY: i32 = -1;

// ---------------------------------------------------------------------------
// Ioctl number definitions (vmm_sys_util macros, must follow struct defs)
// ---------------------------------------------------------------------------

// Scoped to avoid a file-level `#[allow(missing_docs)]` — the ioctl macros
// generate items without doc comments.
#[allow(missing_docs)]
mod ne_ioctls {
    use super::*;
    // Create enclave VM, returns enclave fd via return value.
    ioctl_iowr_nr!(NE_CREATE_VM2, NE_MAGIC, 0x30, NeCreateVmArgs);
    // Add a vCPU to the enclave.
    ioctl_iowr_nr!(NE_ADD_VCPU, NE_MAGIC, 0x21, u32);
    // Get memory offset for image loading.
    ioctl_iowr_nr!(NE_GET_IMAGE_LOAD_INFO, NE_MAGIC, 0x22, NeImageLoadInfo);
    // Donate a memory region to the enclave.
    ioctl_iow_nr!(
        NE_SET_USER_MEMORY_REGION,
        NE_MAGIC,
        0x23,
        NeUserMemoryRegion
    );
    // Start the enclave.
    ioctl_iowr_nr!(NE_START_ENCLAVE, NE_MAGIC, 0x24, NeEnclaveStartInfo);
    // Register a 2 MiB info page for PCIE topology mode.
    ioctl_iow_nr!(NE_SET_INFO_PAGE, NE_MAGIC, 0x25, NeInfoPage);
    // Read matched-flag subset the hypervisor implements (device fd, not enclave fd).
    ioctl_ior_nr!(NE_GET_SUPPORTED_FLAGS, NE_MAGIC, 0x29, u32);
    // Atomically pick and add a vCPU from the kernel NE CPU pool.
    ioctl_iow_nr!(NE_ADD_ANY_VCPU, NE_MAGIC, 0x2D, NeAddAnyVcpuArgs);
}
use ne_ioctls::*;

// ---------------------------------------------------------------------------
// Safe wrappers
// ---------------------------------------------------------------------------

/// Safe wrapper around the `/dev/nitro_enclaves` device fd.
#[derive(Debug)]
pub struct NitroEnclavesDevFd {
    fd: OwnedFd,
}

impl NitroEnclavesDevFd {
    /// Open `/dev/nitro_enclaves`.
    pub fn open() -> std::io::Result<Self> {
        use std::fs::OpenOptions;

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(NE_DEV_PATH)?;
        Ok(Self {
            fd: OwnedFd::from(file),
        })
    }

    /// Allocate physically contiguous (CMA) memory via `mmap(MAP_SHARED)`
    /// on the NE device fd.
    ///
    /// Returns a pointer to the mapped region. The caller is responsible
    /// for calling `munmap` when the memory is no longer needed.
    ///
    /// # Safety
    ///
    /// The returned pointer is valid for `size` bytes.
    pub fn allocate_cma(&self, size: usize) -> Result<*mut u8, std::io::Error> {
        // SAFETY: mmap with MAP_SHARED on the NE device fd allocates CMA
        // memory from the hypervisor's pool. MAP_POPULATE pre-faults pages so
        // they are physically backed before donation to the enclave.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                self.fd.as_raw_fd(),
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        Ok(ptr.cast::<u8>())
    }

    /// Allocate CMA memory with a given alignment.
    ///
    /// Reserves virtual address space, finds an aligned address within it,
    /// then overlays CMA memory via `MAP_FIXED`. Unused prefix/suffix of
    /// the reservation are unmapped.
    ///
    /// Returns `(ptr, aligned_size)` where `ptr` is the aligned CMA base
    /// and `aligned_size` is `size` rounded up to `alignment`.
    pub fn allocate_cma_aligned(
        &self,
        size: usize,
        alignment: usize,
    ) -> Result<(*mut u8, usize), std::io::Error> {
        let aligned_size = align_up!(size, alignment);
        let reserve_size = aligned_size
            .checked_add(alignment)
            .ok_or_else(|| std::io::Error::other("CMA reservation size overflow"))?;

        // Step 1: Reserve VA space for alignment.
        // SAFETY: MAP_ANONYMOUS mmap with PROT_NONE; reserves VA space only.
        let reserve_ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                reserve_size,
                libc::PROT_NONE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        if reserve_ptr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }

        // Step 2: Find aligned address within the reservation.
        let base = reserve_ptr as usize;
        let aligned_addr = align_up!(base, alignment);
        let aligned_ptr = aligned_addr as *mut libc::c_void;

        // Step 3: Overlay CMA memory at the aligned address via MAP_FIXED.
        // MAP_POPULATE pre-faults pages for immediate physical backing.
        // SAFETY: We own the VA range from the reservation.
        let cma_ptr = unsafe {
            libc::mmap(
                aligned_ptr,
                aligned_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_FIXED | libc::MAP_POPULATE,
                self.fd.as_raw_fd(),
                0,
            )
        };
        if cma_ptr == libc::MAP_FAILED {
            let err = std::io::Error::last_os_error();
            // SAFETY: reserve_ptr/reserve_size are from our earlier mmap.
            unsafe { libc::munmap(reserve_ptr, reserve_size) };
            return Err(err);
        }

        // Unmap the unused prefix and suffix of the reservation.
        let prefix_size = aligned_addr - base;
        if prefix_size > 0 {
            // SAFETY: prefix is part of our reservation, not overlapping CMA.
            unsafe { libc::munmap(reserve_ptr, prefix_size) };
        }
        let suffix_start = aligned_addr + aligned_size;
        let suffix_size = (base + reserve_size) - suffix_start;
        if suffix_size > 0 {
            // SAFETY: suffix is part of our reservation, not overlapping CMA.
            unsafe { libc::munmap(suffix_start as *mut libc::c_void, suffix_size) };
        }

        Ok((cma_ptr.cast::<u8>(), aligned_size))
    }

    /// Read the matched-flag subset the hypervisor implements.
    pub fn get_supported_flags(&self) -> std::io::Result<u32> {
        let mut flags: u32 = 0;
        // SAFETY: NE_GET_SUPPORTED_FLAGS ioctl on a valid NE device fd.
        let ret = unsafe { ioctl_with_mut_ref(&self.fd, NE_GET_SUPPORTED_FLAGS(), &mut flags) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(flags)
    }

    /// Create a new enclave VM via NE_CREATE_VM2.
    ///
    /// `flags` is the launch-time flag word recorded at slot allocation by the
    /// hypervisor. It carries every NE_ENCLAVE_*_MODE bit EXCEPT DEBUG (DEBUG
    /// is per-launch and travels with NE_START_ENCLAVE). Returns `(EnclaveFd,
    /// slot_uid)`.
    pub fn create_vm(&self, flags: u32) -> std::io::Result<(EnclaveFd, u64)> {
        let mut args = NeCreateVmArgs {
            flags,
            padding: 0,
            slot_uid: 0,
        };
        // SAFETY: NE_CREATE_VM2 ioctl on a valid NE device fd.
        let ret = unsafe { ioctl_with_mut_ref(&self.fd, NE_CREATE_VM2(), &mut args) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // The ioctl returns the enclave fd as the return value.
        // SAFETY: The kernel returned a valid fd.
        let enclave_fd = EnclaveFd::new(unsafe { OwnedFd::from_raw_fd(ret) });
        Ok((enclave_fd, args.slot_uid))
    }
}

/// Safe wrapper around an enclave instance fd.
#[derive(Debug)]
pub struct EnclaveFd {
    fd: OwnedFd,
}

impl EnclaveFd {
    /// Create from an owned fd returned by [`NitroEnclavesDevFd::create_vm()`].
    pub fn new(fd: OwnedFd) -> Self {
        Self { fd }
    }

    /// Add a specific vCPU to the enclave by CPU ID.
    ///
    /// Use this when explicit `cpu_ids` are configured. Returns the actual
    /// CPU ID assigned.
    pub fn add_vcpu(&self, cpu_id: u32) -> std::io::Result<u32> {
        let mut id = cpu_id;
        // SAFETY: NE_ADD_VCPU ioctl on a valid enclave fd.
        let ret = unsafe { ioctl_with_mut_ref(&self.fd, NE_ADD_VCPU(), &mut id) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(id)
    }

    /// Atomically pick and add a vCPU to the enclave, optionally biased
    /// toward a preferred NUMA node. Uses the NE_ADD_ANY_VCPU ioctl which
    /// avoids the TOCTOU race of the legacy NE_ADD_VCPU(0) path.
    ///
    /// Pass [`NE_NUMA_ANY`] (-1) for no node preference.
    pub fn add_any_vcpu(&self, numa_hint: i32) -> std::io::Result<()> {
        let mut args = NeAddAnyVcpuArgs { numa_hint };
        // SAFETY: NE_ADD_ANY_VCPU ioctl on a valid enclave fd.
        let ret = unsafe { ioctl_with_mut_ref(&self.fd, NE_ADD_ANY_VCPU(), &mut args) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Get the memory offset where the enclave image should be loaded.
    pub fn get_image_load_info(&self) -> std::io::Result<NeImageLoadInfo> {
        let mut info = NeImageLoadInfo {
            flags: image_load_flags::NE_EIF_IMAGE,
            memory_offset: 0,
        };
        // SAFETY: NE_GET_IMAGE_LOAD_INFO ioctl on a valid enclave fd.
        let ret = unsafe { ioctl_with_mut_ref(&self.fd, NE_GET_IMAGE_LOAD_INFO(), &mut info) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(info)
    }

    /// Set a user memory region for the enclave.
    pub fn set_user_memory_region(&self, addr: u64, size: u64) -> std::io::Result<()> {
        let region = NeUserMemoryRegion {
            flags: 0,
            memory_size: size,
            userspace_addr: addr,
        };
        // SAFETY: NE_SET_USER_MEMORY_REGION ioctl on a valid enclave fd.
        let ret = unsafe { ioctl_with_ref(&self.fd, NE_SET_USER_MEMORY_REGION(), &region) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Start the enclave with explicit flags. Returns the assigned CID.
    ///
    /// `flags` is a bitmask of `start_flags::*` constants.
    pub fn start(&self, flags: u64, cid: u64) -> std::io::Result<u64> {
        let mut info = NeEnclaveStartInfo {
            flags,
            enclave_cid: cid,
        };
        // SAFETY: NE_START_ENCLAVE ioctl on a valid enclave fd.
        let ret = unsafe { ioctl_with_mut_ref(&self.fd, NE_START_ENCLAVE(), &mut info) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(info.enclave_cid)
    }

    /// Register a 2 MiB info page for PCIE topology mode.
    pub fn set_info_page(&self, addr: u64, size: u64) -> std::io::Result<()> {
        let page = NeInfoPage {
            userspace_addr: addr,
            size,
        };
        // SAFETY: NE_SET_INFO_PAGE ioctl on a valid enclave fd.
        let ret = unsafe { ioctl_with_ref(&self.fd, NE_SET_INFO_PAGE(), &page) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

impl AsRawFd for NitroEnclavesDevFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl AsRawFd for EnclaveFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

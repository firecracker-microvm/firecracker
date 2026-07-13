// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Nitro Enclaves kernel ioctl bindings.
//!
//! These structures and constants match the Nitro Enclaves kernel UAPI.

use std::fs::File;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;

use vm_memory::{FileOffset, GuestAddress};
use vmm_sys_util::ioctl::{ioctl_with_mut_ref, ioctl_with_ref};
use vmm_sys_util::{ioctl_ior_nr, ioctl_iow_nr, ioctl_iowr_nr};

use crate::vstate::memory::{GuestRegionMmap, MemoryError};

/// Path to the Nitro Enclaves device node.
const NE_DEV_PATH: &str = "/dev/nitro_enclaves";

/// Alignment NE requires for every donated region (RAM, DMB, info page).
const NE_REGION_ALIGN: usize = 2 * 1024 * 1024;

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
    /// Host-scheduled (floating) vCPUs sharing the parent's overcommit pool,
    /// instead of dedicated pinned cores (matched, bit 11).
    pub const NE_ENCLAVE_CPU_OVERCOMMIT_MODE: u64 = 1 << 11;
    /// Host-side per-vCPU time accounting / Parent-PID visibility (matched, bit 12).
    pub const NE_ENCLAVE_CPU_ACCOUNTING_MODE: u64 = 1 << 12;
    /// Request explicit multi-NUMA placement (matched, bit 13).
    pub const NE_ENCLAVE_PCIE_NUMA_MODE: u64 = 1 << 13;
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
/// optionally biased toward a preferred parent NUMA node.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct NeAddAnyVcpuArgs {
    /// Preferred parent NUMA node, or [`NE_NUMA_ANY`] (-1) for no preference.
    pub numa_hint: i32,
}

/// No NUMA preference — pick from any node.
pub const NE_NUMA_ANY: i32 = -1;

// ---------------------------------------------------------------------------
// Device attachment structures (NE_ADD_DEVICE and notification wiring)
// ---------------------------------------------------------------------------

/// Maximum device-specific config size (matches NE_DEVICE_CONFIG_MAX_SIZE in UAPI).
pub const NE_DEVICE_CONFIG_MAX_SIZE: usize = 256;

/// Maximum virtqueues per device (matches NE_MAX_VQS in UAPI).
pub const NE_MAX_VQS: usize = 64;

/// SHM region id for Device Memory Buffer.
pub const VIRTIO_SHMEM_ID_DMB: u8 = 2;

/// Device class: standard virtio device.
pub const NE_DEVICE_CLASS_VIRTIO: u32 = 0x0000;

/// Shared memory region descriptor (userspace -> kernel).
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct NeShmRegion {
    /// SHM region identifier.
    pub shm_id: u8,
    /// Reserved, must be zero.
    pub reserved: [u8; 7],
    /// Userspace virtual address of the mmap'd region.
    pub userspace_addr: u64,
    /// Size in bytes.
    pub size: u64,
}

/// Per-VQ info returned by NE_ADD_DEVICE.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct NeVqInfo {
    /// MSI-X vector assigned to this VQ.
    pub msix_vector: u16,
    /// Notify index for this VQ.
    pub notify_index: u16,
    /// Opaque MSI-X table index from SM (for NE_SET_VRING_KICK).
    pub msix_entry: u16,
    /// Opaque BAR4 byte offset from SM (for NE_SET_VRING_CALL).
    pub bar4_doorbell_offset: u16,
}

/// Device add request for NE_ADD_DEVICE (in/out).
#[repr(C)]
#[derive(Clone, Debug)]
pub struct NeAddDevice {
    /// Device type (class << 16 | subtype).
    pub device_type: u32,
    /// Number of virtqueues.
    pub num_vqs: u32,
    /// Size of device-specific config, in bytes.
    pub config_size: u32,
    /// Per-device info-event MSI-X vector (output, 0 if unsupported).
    pub info_event_vector: u16,
    /// Reserved field.
    pub reserved: u16,
    /// Virtio device feature bitmap, 512 bits.
    pub device_features: [u8; 64],
    /// Device-specific configuration data.
    pub device_config: [u8; NE_DEVICE_CONFIG_MAX_SIZE],
    /// Number of shared memory regions.
    pub num_shm_regions: u32,
    /// Reserved field.
    pub reserved2: u32,
    /// Userspace pointer to array of NeShmRegion.
    pub shm_regions_ptr: u64,
    /// Assigned device UID (output).
    pub device_uid: u64,
    /// Per-VQ info (output).
    pub vq_info: [NeVqInfo; NE_MAX_VQS],
}

impl Default for NeAddDevice {
    fn default() -> Self {
        // SAFETY: NeAddDevice is #[repr(C)] and all-zero is a valid state.
        unsafe { std::mem::zeroed() }
    }
}

/// Wire an eventfd for parent-to-enclave (call) notifications: when the parent
/// writes the fd, the NE driver delivers an MSI-X interrupt to the enclave guest.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct NeVringCall {
    /// Device UID from NE_ADD_DEVICE.
    pub device_uid: u64,
    /// Eventfd to signal.
    pub fd: i32,
    /// Opaque BAR4 byte offset (in bytes) from SM (via
    /// `NeVqInfo::bar4_doorbell_offset`).
    pub bar4_doorbell_offset: u16,
    /// Reserved field.
    pub reserved: u16,
}

/// Wire an eventfd for enclave-to-parent (kick) notifications: when the enclave
/// guest kicks a queue, the NE driver signals the fd so the parent's device
/// backend processes it.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct NeVringKick {
    /// Device UID from NE_ADD_DEVICE.
    pub device_uid: u64,
    /// Eventfd to signal.
    pub fd: i32,
    /// MSI-X vector for this VQ.
    pub msix_vector: u16,
    /// Reserved field.
    pub reserved: u16,
}

/// Wire an eventfd to a per-device info-event MSI-X vector.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct NeInfoEventFd {
    /// Eventfd to signal on info-page change; -1 to unbind.
    pub fd: i32,
    /// NE device MSI-X vector index (from NeAddDevice::info_event_vector).
    pub vector: u16,
    /// Reserved field.
    pub reserved: u16,
}

/// Maximum bytes NE_UPDATE_DEVICE_CONFIG can push.
pub const NE_UPDATE_CONFIG_MAX_SIZE: usize = 64;

/// NE_UPDATE_DEVICE_CONFIG ioctl payload. Pushes updated device-specific
/// config bytes to a running enclave
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NeUpdateDeviceConfig {
    /// Device UID from NE_ADD_DEVICE.
    pub device_uid: u64,
    /// Number of valid bytes in `config_data` (1..=64).
    pub config_size: u32,
    /// Byte offset into the device config space.
    pub config_offset: u32,
    /// Config bytes to write at `config_offset`.
    pub config_data: [u8; NE_UPDATE_CONFIG_MAX_SIZE],
}

const _: () = assert!(std::mem::size_of::<NeUpdateDeviceConfig>() == 80);

/// NE_ACCOUNT_VCPU ioctl payload (`struct ne_account_vcpu_params`, 8 bytes).
///
/// Binds the calling thread (task) to an enclave vCPU so the NE driver can
/// attribute that vCPU's KVM_RUN time to the task (Parent-PID visibility).
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct NeAccountVcpuParams {
    /// Zero-based enclave vCPU index to bind the caller task to.
    pub vcpu_idx: u32,
    /// Reserved, must be zero.
    pub reserved: u32,
}

const _: () = assert!(std::mem::size_of::<NeAccountVcpuParams>() == 8);

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
    // Add a virtio device to the enclave.
    ioctl_iowr_nr!(NE_ADD_DEVICE, NE_MAGIC, 0x26, NeAddDevice);
    // Wire an eventfd to a BAR4 notify offset (call direction).
    ioctl_iow_nr!(NE_SET_VRING_CALL, NE_MAGIC, 0x27, NeVringCall);
    // Wire an NE device MSI-X vector to an eventfd (kick direction).
    ioctl_iow_nr!(NE_SET_VRING_KICK, NE_MAGIC, 0x28, NeVringKick);
    // Read matched-flag subset the hypervisor implements (device fd, not enclave fd).
    ioctl_ior_nr!(NE_GET_SUPPORTED_FLAGS, NE_MAGIC, 0x29, u32);
    // Register the calling thread as an enclave vCPU's host-side accounting target.
    ioctl_iow_nr!(NE_ACCOUNT_VCPU, NE_MAGIC, 0x2A, NeAccountVcpuParams);
    // Wire an eventfd to a per-device info-event MSI-X vector.
    ioctl_iow_nr!(NE_SET_INFO_EVENT_FD, NE_MAGIC, 0x2B, NeInfoEventFd);
    // Push updated device config bytes to a running enclave.
    ioctl_iow_nr!(
        NE_UPDATE_DEVICE_CONFIG,
        NE_MAGIC,
        0x2C,
        NeUpdateDeviceConfig
    );
    // Atomically pick and add a vCPU from the kernel NE CPU pool.
    ioctl_iow_nr!(NE_ADD_ANY_VCPU, NE_MAGIC, 0x2D, NeAddAnyVcpuArgs);
}
use ne_ioctls::*;

// ---------------------------------------------------------------------------
// NE-specific error codes
// ---------------------------------------------------------------------------

/// A Nitro Enclaves driver error code.
///
/// NE ioctls fail with either a standard Linux errno or an NE-specific code that
/// libc cannot name (it would show as an opaque `os error 272`). Variant names
/// and `#[repr(i32)]` discriminants mirror the UAPI `NE_ERR_*` symbols verbatim,
/// so an in-range errno maps to a variant by its discriminant.
///
/// Each doc comment is the bare description; [`last_ioctl_error`] appends the
/// name and code when rendering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, displaydoc::Display)]
#[repr(i32)]
#[allow(non_camel_case_types)]
// Variants are materialized by `from_code`'s transmute, which dead-code
// analysis cannot see; they exist to give each errno a name and description.
#[allow(dead_code)]
enum NeError {
    /// the provided vCPU is already used
    NE_ERR_VCPU_ALREADY_USED = NeError::NE_ERR_MIN,
    /// the provided vCPU is not available in the NE CPU pool
    NE_ERR_VCPU_NOT_IN_CPU_POOL,
    /// the core id of the provided vCPU is invalid or out of range of the NE CPU pool
    NE_ERR_VCPU_INVALID_CPU_CORE,
    /// the memory region size is not a multiple of 2 MiB
    NE_ERR_INVALID_MEM_REGION_SIZE,
    /// the memory region address range is invalid
    NE_ERR_INVALID_MEM_REGION_ADDR,
    /// the memory region address is not aligned
    NE_ERR_UNALIGNED_MEM_REGION_ADDR,
    /// the memory region is already used
    NE_ERR_MEM_REGION_ALREADY_USED,
    /// the memory region is not backed by contiguous physical huge page(s)
    NE_ERR_MEM_NOT_HUGE_PAGE,
    /// the memory region is backed by pages from a different NUMA node than the CPUs
    NE_ERR_MEM_DIFFERENT_NUMA_NODE,
    /// the max number of memory regions per enclave has been reached
    NE_ERR_MEM_MAX_REGIONS,
    /// enclave start was triggered with no memory regions added
    NE_ERR_NO_MEM_REGIONS_ADDED,
    /// enclave start was triggered with no vCPUs added
    NE_ERR_NO_VCPUS_ADDED,
    /// the enclave memory size is lower than the minimum supported
    NE_ERR_ENCLAVE_MEM_MIN_SIZE,
    /// enclave start was triggered without full CPU cores set
    NE_ERR_FULL_CORES_NOT_USED,
    /// the enclave is not in init state
    NE_ERR_NOT_IN_INIT_STATE,
    /// the provided vCPU is out of range of the available CPUs
    NE_ERR_INVALID_VCPU,
    /// no CPUs are available in the NE CPU pool
    NE_ERR_NO_CPUS_AVAIL_IN_POOL,
    /// the memory region is not backed by pages multiple of 2 MiB
    NE_ERR_INVALID_PAGE_SIZE,
    /// the provided flag value is invalid
    NE_ERR_INVALID_FLAG_VALUE,
    /// the provided enclave CID is invalid
    NE_ERR_INVALID_ENCLAVE_CID,
    /// the enclave is not in running state
    NE_ERR_NOT_IN_RUNNING_STATE,
    /// Exclusive upper bound; append new NE codes immediately above this line.
    NE_ERR_MAX,
}

impl NeError {
    /// Lowest NE-specific error code; a literal, as the first variant derives
    /// its discriminant from it (deriving this from that variant is circular).
    const NE_ERR_MIN: i32 = 256;

    /// Decode an errno into an `NeError`, or `None` if it is not an NE code.
    fn from_code(code: i32) -> Option<Self> {
        if !(Self::NE_ERR_MIN..Self::NE_ERR_MAX as i32).contains(&code) {
            return None;
        }
        // SAFETY: `NeError` is a field-less `#[repr(i32)]` enum whose
        // discriminants are contiguous from NE_ERR_MIN up to (excluding)
        // NE_ERR_MAX. The check above restricts `code` to exactly that range,
        // so it is always a valid discriminant.
        Some(unsafe { std::mem::transmute::<i32, NeError>(code) })
    }
}

/// The current `errno` as a [`std::io::Error`], naming an NE-specific code and
/// preserving a standard errno verbatim. Used at every ioctl failure site.
fn last_ioctl_error() -> std::io::Error {
    let err = std::io::Error::last_os_error();
    match err.raw_os_error().and_then(NeError::from_code) {
        Some(ne) => std::io::Error::other(format!("{ne:?} (errno={}): {ne}", ne as i32)),
        None => err,
    }
}

// ---------------------------------------------------------------------------
// Safe wrappers
// ---------------------------------------------------------------------------

/// Safe wrapper around the `/dev/nitro_enclaves` device fd.
///
/// `Arc<File>` so CMA regions can share the fd via a `FileOffset`.
#[derive(Debug)]
pub struct NitroEnclavesDevFd {
    fd: Arc<File>,
}

impl NitroEnclavesDevFd {
    /// Open `/dev/nitro_enclaves`.
    pub fn open() -> std::io::Result<Self> {
        use std::fs::OpenOptions;

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(NE_DEV_PATH)?;
        Ok(Self { fd: Arc::new(file) })
    }

    /// Allocate an owning [`GuestRegionMmap`] of `size` CMA memory on the NE
    /// device, mapped `MAP_SHARED | MAP_POPULATE` at `guest_base`. The region
    /// owns its mapping and `munmap`s it on drop.
    ///
    /// `size` must be a multiple of 2 MiB (NE donation requires it).
    ///
    /// The region shares the device fd via a `FileOffset` so it can outlive
    /// this handle.
    ///
    /// `parent_numa` pins the CMA pages to a parent NUMA node. `parent_numa << 48` is
    /// the NE driver's node selector; the driver has no "any node" encoding here,
    /// so offset 0 selects node 0.
    pub fn allocate_cma_region(
        &self,
        guest_base: GuestAddress,
        size: usize,
        prot: libc::c_int,
        parent_numa: u16,
    ) -> Result<GuestRegionMmap, MemoryError> {
        let mmap_offset = u64::from(parent_numa) << 48;
        let region = GuestRegionMmap::allocate(
            guest_base,
            size,
            prot,
            libc::MAP_SHARED | libc::MAP_POPULATE,
            Some(FileOffset::from_arc(Arc::clone(&self.fd), mmap_offset)),
            false,
        )?;
        // NE requires 2 MiB-aligned regions; the allocator's alignment is a
        // KVM/THP concern that could drift, so assert rather than assume.
        assert_eq!(
            region.as_ptr() as usize % NE_REGION_ALIGN,
            0,
            "CMA region base must be 2 MiB-aligned for Nitro Enclaves"
        );
        Ok(region)
    }

    /// Read the matched-flag subset the hypervisor implements.
    pub fn get_supported_flags(&self) -> std::io::Result<u32> {
        let mut flags: u32 = 0;
        // SAFETY: NE_GET_SUPPORTED_FLAGS ioctl on a valid NE device fd.
        let ret = unsafe { ioctl_with_mut_ref(&self.fd, NE_GET_SUPPORTED_FLAGS(), &mut flags) };
        if ret < 0 {
            return Err(last_ioctl_error());
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
            return Err(last_ioctl_error());
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

    /// Duplicate the enclave fd (a new fd referring to the same open enclave).
    pub fn try_clone(&self) -> std::io::Result<Self> {
        Ok(Self {
            fd: self.fd.try_clone()?,
        })
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
            return Err(last_ioctl_error());
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
            return Err(last_ioctl_error());
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
            return Err(last_ioctl_error());
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
            return Err(last_ioctl_error());
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
            return Err(last_ioctl_error());
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
            return Err(last_ioctl_error());
        }
        Ok(())
    }

    /// Add a virtio device to the enclave.
    ///
    /// Populates output fields in `req`: `device_uid`, `info_event_vector`, `vq_info`.
    pub fn add_device(&self, req: &mut NeAddDevice) -> std::io::Result<()> {
        // SAFETY: NE_ADD_DEVICE ioctl on a valid enclave fd.
        let ret = unsafe { ioctl_with_mut_ref(&self.fd, NE_ADD_DEVICE(), req) };
        if ret < 0 {
            return Err(last_ioctl_error());
        }
        Ok(())
    }

    /// Wire an eventfd for parent-to-enclave (call) notifications.
    ///
    /// When the parent writes to this fd, the NE driver delivers a BAR4 write
    /// that triggers an MSI-X interrupt in the enclave guest.
    pub fn set_vring_call(
        &self,
        device_uid: u64,
        bar4_doorbell_offset: u16,
        fd: RawFd,
    ) -> std::io::Result<()> {
        let req = NeVringCall {
            device_uid,
            fd,
            bar4_doorbell_offset,
            reserved: 0,
        };
        // SAFETY: NE_SET_VRING_CALL ioctl on a valid enclave fd.
        let ret = unsafe { ioctl_with_ref(&self.fd, NE_SET_VRING_CALL(), &req) };
        if ret < 0 {
            return Err(last_ioctl_error());
        }
        Ok(())
    }

    /// Wire an NE device MSI-X vector to an eventfd (kick direction).
    ///
    /// When the enclave guest kicks a virtqueue, the NE driver signals this fd
    /// so the device backend wakes and processes the available ring.
    pub fn set_vring_kick(
        &self,
        device_uid: u64,
        msix_vector: u16,
        fd: RawFd,
    ) -> std::io::Result<()> {
        let req = NeVringKick {
            device_uid,
            fd,
            msix_vector,
            reserved: 0,
        };
        // SAFETY: NE_SET_VRING_KICK ioctl on a valid enclave fd.
        let ret = unsafe { ioctl_with_ref(&self.fd, NE_SET_VRING_KICK(), &req) };
        if ret < 0 {
            return Err(last_ioctl_error());
        }
        Ok(())
    }

    /// Wire an eventfd to a per-device info-event MSI-X vector.
    ///
    /// The kernel signals this fd when the device's info-page mirror changes
    /// (e.g. DRIVER_OK set). Pass `fd = -1` to unbind.
    pub fn set_info_event_fd(&self, vector: u16, fd: RawFd) -> std::io::Result<()> {
        let req = NeInfoEventFd {
            fd,
            vector,
            reserved: 0,
        };
        // SAFETY: NE_SET_INFO_EVENT_FD ioctl on a valid enclave fd.
        let ret = unsafe { ioctl_with_ref(&self.fd, NE_SET_INFO_EVENT_FD(), &req) };
        if ret < 0 {
            return Err(last_ioctl_error());
        }
        Ok(())
    }

    /// Push updated device config bytes to the running enclave.
    ///
    /// The enclave VMM updates its copy of the device config space and
    /// injects a config-change interrupt to the enclave guest.
    pub fn update_device_config(
        &self,
        device_uid: u64,
        config_offset: u32,
        config: &[u8],
    ) -> std::io::Result<()> {
        if config.is_empty() || config.len() > NE_UPDATE_CONFIG_MAX_SIZE {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
        }
        let config_size = u32::try_from(config.len()).unwrap();
        if config_offset
            .checked_add(config_size)
            .is_none_or(|config_end| config_end > u32::try_from(NE_DEVICE_CONFIG_MAX_SIZE).unwrap())
        {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
        }

        let mut req = NeUpdateDeviceConfig {
            device_uid,
            config_size,
            config_offset,
            config_data: [0; NE_UPDATE_CONFIG_MAX_SIZE],
        };
        req.config_data[..config.len()].copy_from_slice(config);
        // SAFETY: NE_UPDATE_DEVICE_CONFIG ioctl on a valid enclave fd.
        let ret = unsafe { ioctl_with_ref(&self.fd, NE_UPDATE_DEVICE_CONFIG(), &req) };
        if ret < 0 {
            return Err(last_ioctl_error());
        }
        Ok(())
    }

    /// Register the calling thread as the host-side accounting target for
    /// enclave vCPU `vcpu_idx` (Parent-PID visibility).
    ///
    /// Only valid on an enclave created with `NE_ENCLAVE_CPU_ACCOUNTING_MODE`,
    /// after `NE_START_ENCLAVE`. The NE driver then attributes the vCPU's guest
    /// time to the calling thread, so it shows up as that thread's guest time.
    pub fn account_vcpu(&self, vcpu_idx: u32) -> std::io::Result<()> {
        let mut params = NeAccountVcpuParams {
            vcpu_idx,
            reserved: 0,
        };
        // SAFETY: NE_ACCOUNT_VCPU ioctl on a valid enclave fd.
        let ret = unsafe { ioctl_with_mut_ref(&self.fd, NE_ACCOUNT_VCPU(), &mut params) };
        if ret < 0 {
            return Err(last_ioctl_error());
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

#[cfg(test)]
mod tests {

    use super::ne_ioctls::{NE_ACCOUNT_VCPU, NE_UPDATE_DEVICE_CONFIG};
    use super::*;

    impl EnclaveFd {
        /// An EnclaveFd backed by /dev/null: every ioctl fails with ENOTTY, so
        /// tests can exercise pre-ioctl paths or assert the ioctl was reached.
        pub(crate) fn dev_null() -> Self {
            Self::new(std::fs::File::open("/dev/null").unwrap().into())
        }
    }

    #[test]
    fn test_ne_account_vcpu_ioctl_value() {
        // _IOW(0xAE, 0x2A, 8) = (1<<30) | (8<<16) | (0xAE<<8) | 0x2A.
        // One less than NE_SET_INFO_EVENT_FD (1074310699).
        assert_eq!(NE_ACCOUNT_VCPU(), 1074310698);
    }

    #[test]
    fn test_ne_error_decodes_specific_codes() {
        let ne = NeError::from_code(272).unwrap();
        assert_eq!(ne.to_string(), "no CPUs are available in the NE CPU pool");
        assert_eq!(format!("{ne:?}"), "NE_ERR_NO_CPUS_AVAIL_IN_POOL");
        assert_eq!(ne as i32, 272);
        // The rendering last_ioctl_error assembles.
        assert_eq!(
            format!("{ne:?} (errno={}): {ne}", ne as i32),
            "NE_ERR_NO_CPUS_AVAIL_IN_POOL (errno=272): no CPUs are available in the NE CPU pool"
        );
    }

    #[test]
    fn test_ne_error_range_is_contiguous() {
        // Guards the contiguity the transmute in from_code relies on.
        for code in NeError::NE_ERR_MIN..NeError::NE_ERR_MAX as i32 {
            let ne = NeError::from_code(code)
                .unwrap_or_else(|| panic!("NE code {code} should decode to a named variant"));
            assert_eq!(ne as i32, code, "discriminant must equal the wire code");
        }
    }

    #[test]
    fn test_ne_error_passes_through_standard_errno() {
        // A standard errno is outside the NE range, so from_code rejects it.
        assert!(NeError::from_code(libc::EINVAL).is_none());
    }

    #[test]
    fn test_ne_update_device_config_ioctl_value() {
        // _IOW(0xAE, 0x2C, 80) = (1<<30) | (80<<16) | (0xAE<<8) | 0x2C.
        // Must match the value allowed in resources/seccomp/*.json.
        assert_eq!(NE_UPDATE_DEVICE_CONFIG(), 1079029292);
    }

    #[test]
    fn test_update_device_config_rejects_bad_arguments() {
        let fd = EnclaveFd::dev_null();
        assert_eq!(
            fd.update_device_config(1, 0, &[]).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
        assert_eq!(
            fd.update_device_config(1, 0, &[0; NE_UPDATE_CONFIG_MAX_SIZE + 1])
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidInput
        );
        assert_eq!(
            fd.update_device_config(1, u32::MAX, &[0])
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn test_update_device_config_issues_ioctl() {
        // /dev/null rejects every ioctl with ENOTTY, so reaching that error
        // proves a valid nonzero-offset range passes validation and the ioctl is issued.
        let err = EnclaveFd::dev_null()
            .update_device_config(1, 1, &[0; NE_UPDATE_CONFIG_MAX_SIZE - 1])
            .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ENOTTY));
    }
}

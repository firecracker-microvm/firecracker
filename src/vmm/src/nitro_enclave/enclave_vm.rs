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
use crate::utils::{mib_to_bytes, u64_to_usize};
use crate::vmm_config::enclave::{EnclaveConfig, EnclaveNumaNode};
use crate::vstate::memory::{GuestMemoryMmap, GuestRegionMmapExt, MemoryError};

/// Maximum vCPUs for the Nitro Enclave path.
///
/// This is an arbitrary sanity-check limit — the actual maximum depends on the
/// underlying hardware and the Nitro hypervisor, which enforce it at boot.
pub const MAX_SUPPORTED_ENCLAVE_VCPUS: u16 = 1024;

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
    /// Failed to add a vCPU on parent NUMA node {numa_hint}: {source}
    AddAnyVcpu {
        /// Parent NUMA node the vCPU was requested on.
        numa_hint: i32,
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
    /// Normalized running config (numa_nodes sorted); source of truth for
    /// `GET /enclave`.
    config: EnclaveConfig,
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

    /// Guest-physical base and max chunk length at cumulative `offset` bytes
    /// into the enclave RAM, clamped so a chunk never crosses the PCI MMIO hole.
    fn gpa_chunk_for_offset(offset: usize, remaining: usize) -> (u64, usize) {
        if offset >= Self::LOW_RAM_MAX_SIZE {
            let gpa = Self::HIGH_RAM_BASE + (offset - Self::LOW_RAM_MAX_SIZE) as u64;
            (gpa, remaining)
        } else {
            let to_boundary = Self::LOW_RAM_MAX_SIZE - offset;
            (
                Self::ENCLAVE_RAM_BASE + offset as u64,
                remaining.min(to_boundary),
            )
        }
    }

    /// Split the enclave's RAM into the `(gpa, size, parent_numa)` CMA regions to
    /// allocate and donate, around the PCI MMIO hole.
    ///
    /// Each region is donated as its own owning CMA region and the hypervisor
    /// concatenates them in donation order, so guest node K's base is the running
    /// sum of the prior sizes -- which is why the nodes must be in
    /// ascending-`parent_numa` order.
    fn split_ram_regions(numa_nodes: &[EnclaveNumaNode]) -> Vec<(GuestAddress, usize, u16)> {
        let mut regions = Vec::new();
        let mut offset: usize = 0;
        for node in numa_nodes {
            let mut remaining = mib_to_bytes(node.mem_size_mib);
            while remaining > 0 {
                let (gpa, chunk) = Self::gpa_chunk_for_offset(offset, remaining);
                regions.push((GuestAddress(gpa), chunk, node.parent_numa));
                offset += chunk;
                remaining -= chunk;
            }
        }
        regions
    }

    /// Create a new enclave VM from a pre-opened device fd, issuing
    /// `NE_CREATE_VM2` with `create_flags`.
    ///
    /// `create_flags` carries every NE_ENCLAVE_*_MODE bit EXCEPT DEBUG
    /// (DEBUG is per-launch and travels with NE_START_ENCLAVE).
    pub fn new(
        dev_fd: NitroEnclavesDevFd,
        create_flags: u32,
        config: EnclaveConfig,
    ) -> Result<Self, EnclaveVmError> {
        let (enclave_fd, slot_uid) = dev_fd
            .create_vm(create_flags)
            .map_err(EnclaveVmError::CreateVm)?;

        Ok(Self {
            accounting_threads: None,
            dev_fd,
            enclave_fd,
            slot_uid,
            config,
            info_page: None,
            enclave_ram: None,
            console: None,
        })
    }

    /// Slot UID assigned by the hypervisor.
    pub fn slot_uid(&self) -> u64 {
        self.slot_uid
    }

    /// The config the enclave is running with.
    pub fn config(&self) -> EnclaveConfig {
        self.config.clone()
    }

    /// Whether the enclave was started with PCIE hotplug mode.
    pub fn hotplug_enabled(&self) -> bool {
        self.config.hotplug_mode
    }

    /// Per-device DMB size in MiB for confidential mode; `None` in direct mode.
    pub fn dmb_size_mib(&self) -> Option<u64> {
        self.config.dmb_size_mib()
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
            .map_err(|source| EnclaveVmError::AddAnyVcpu { numa_hint, source })?;
        Ok(())
    }

    /// Allocate CMA memory, copy the EIF image into it, then donate the
    /// memory to the NE driver.
    ///
    /// The EIF must be written before donation: `NE_SET_USER_MEMORY_REGION`
    /// makes the pages inaccessible to the parent in confidential mode. The
    /// donated memory is retained for the enclave's lifetime (dropping would
    /// `munmap` it): direct mode exposes it as device DMA memory, confidential
    /// mode keeps it PROT_NONE.
    pub fn load_and_add_memory(
        &mut self,
        eif_data: &[u8],
        direct_mode: bool,
        numa_nodes: &[EnclaveNumaNode],
    ) -> Result<(), EnclaveVmError> {
        let ram_regions = Self::split_ram_regions(numa_nodes);

        // Verify the EIF fits in low RAM (guest node 0) before allocating any
        // CMA, so an oversized image fails cheaply. It must fit that chunk, else
        // image bytes would spill onto another NUMA node.
        let load_info = self
            .enclave_fd
            .get_image_load_info()
            .map_err(EnclaveVmError::GetImageLoadInfo)?;
        let offset = u64_to_usize(load_info.memory_offset);
        let first_region_size = ram_regions[0].1;
        if offset + eif_data.len() > first_region_size {
            return Err(EnclaveVmError::ImageTooLarge {
                offset: offset as u64,
                image_size: eif_data.len() as u64,
                mem_size: first_region_size as u64,
            });
        }

        // Allocate one owning CMA region per RAM region and donate each.
        // Read-write: the EIF is written here before donation, and direct mode
        // keeps using the regions as device DMA memory afterwards.
        let regions = ram_regions
            .iter()
            .enumerate()
            .map(|(idx, &(gpa, region_size, parent_numa))| {
                let region = self
                    .dev_fd
                    .allocate_cma_region(
                        gpa,
                        region_size,
                        libc::PROT_READ | libc::PROT_WRITE,
                        parent_numa,
                    )
                    .map_err(EnclaveVmError::CmaAlloc)?;
                info!(
                    "CMA alloc: gpa={:#x} host={:#x} size={} MiB parent_numa={}",
                    gpa.0,
                    region.as_ptr() as usize,
                    region.len() / (1024 * 1024),
                    parent_numa,
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

        for region in guest_mem.iter() {
            self.enclave_fd
                .set_user_memory_region(region.as_ptr() as u64, region.len())
                .map_err(EnclaveVmError::SetMemoryRegion)?;
        }

        self.enclave_ram = Some(if direct_mode {
            EnclaveRam::Direct(guest_mem)
        } else {
            // Donation revoked the parent's access; PROT_NONE to match.
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
        let page = InfoPage::new(&self.dev_fd, self.guest_node0_parent_numa())
            .map_err(EnclaveVmError::InfoPageAlloc)?;
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
            // Last drain, so there is no further polling to stop.
            let _ = console
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

    /// Parent NUMA node backing guest node 0, for parent-facing CMA regions (the
    /// info page and the DMBs). numa_nodes is sorted ascending, so element 0 is
    /// guest node 0; falls back to node 0 when no placement is set.
    fn guest_node0_parent_numa(&self) -> u16 {
        self.config
            .numa_nodes
            .as_deref()
            .and_then(<[_]>::first)
            .map_or(0, |n| n.parent_numa)
    }

    /// Allocate a Device Memory Buffer (DMB) for a confidential-mode device.
    ///
    /// The DMB is a CMA-backed region from the NE driver's pool, shared with the
    /// enclave so that virtqueue rings stay accessible to the parent while the
    /// rest of the enclave RAM is isolated. It is returned as a single-region
    /// `GuestMemoryMmap` at `GuestAddress(0)`; the region owns its CMA mapping
    /// and munmaps it on drop. Pinned to guest node 0's parent node.
    pub fn create_dmb(&self, size_bytes: usize) -> Result<GuestMemoryMmap, EnclaveVmError> {
        // Read-write: the parent services queue rings in this DMA memory.
        let region = self
            .dev_fd
            .allocate_cma_region(
                GuestAddress(0),
                size_bytes,
                libc::PROT_READ | libc::PROT_WRITE,
                self.guest_node0_parent_numa(),
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

    /// Multi-node placements whose per-node sizes are 128 MiB section multiples,
    /// as `validate_numa_config` requires, on ascending parent nodes.
    fn numa_placements() -> impl Strategy<Value = Vec<EnclaveNumaNode>> {
        proptest::collection::vec(1usize..=20, 2..=5).prop_map(|sections| {
            sections
                .into_iter()
                .zip(0u16..)
                .map(|(n, parent_numa)| numa_node(parent_numa, 2, n * 128))
                .collect()
        })
    }

    proptest! {
        // Span sizes below, at, and well above the MMIO hole so both the
        // single-region and split cases (incl. the boundary) are exercised.
        #[test]
        fn test_split_ram_regions(mib in 1usize..=(EnclaveVm::LOW_RAM_MAX_SIZE * 2 / (1024 * 1024))) {
            // The default placement: one node on parent node 0, as
            // validate_numa_config synthesizes when the request omits numa_nodes.
            let nodes = vec![numa_node(0, 1, mib)];
            let size = mib_to_bytes(mib);
            let ram_regions = EnclaveVm::split_ram_regions(&nodes);

            // The regions exactly cover `size`, low region first at the RAM base.
            let total: usize = ram_regions.iter().map(|&(_, s, _)| s).sum();
            prop_assert_eq!(total, size);
            prop_assert_eq!(ram_regions[0].0, GuestAddress(EnclaveVm::ENCLAVE_RAM_BASE));
            prop_assert!(ram_regions[0].1 <= EnclaveVm::LOW_RAM_MAX_SIZE);
            // Everything lands on the one configured node.
            prop_assert!(ram_regions.iter().all(|&(_, _, parent_numa)| parent_numa == 0));

            if size > EnclaveVm::LOW_RAM_MAX_SIZE {
                // Split around the hole: low region fills it, overflow lands high.
                prop_assert_eq!(ram_regions.len(), 2);
                prop_assert_eq!(ram_regions[0].1, EnclaveVm::LOW_RAM_MAX_SIZE);
                prop_assert_eq!(ram_regions[1].0, GuestAddress(EnclaveVm::HIGH_RAM_BASE));
            } else {
                prop_assert_eq!(ram_regions.len(), 1);
            }
        }

        #[test]
        fn test_split_ram_regions_numa(nodes in numa_placements()) {
            let total: usize = nodes.iter().map(|n| mib_to_bytes(n.mem_size_mib)).sum();
            let regions = EnclaveVm::split_ram_regions(&nodes);

            prop_assert_eq!(regions.iter().map(|&(_, s, _)| s).sum::<usize>(), total);
            prop_assert!(regions.iter().all(|&(_, size, _)| size > 0));
            prop_assert_eq!(regions[0].0, GuestAddress(EnclaveVm::ENCLAVE_RAM_BASE));

            for &(gpa, size, _) in &regions {
                let end = gpa.0 + size as u64;
                if gpa.0 < EnclaveVm::PCIE_MMIO_BASE {
                    prop_assert!(end <= EnclaveVm::PCIE_MMIO_BASE);
                } else {
                    prop_assert!(gpa.0 >= EnclaveVm::HIGH_RAM_BASE);
                }
            }

            // Strictly ascending, and contiguous except for the single jump over
            // the hole. `GuestMemoryMmap::from_regions` rejects unsorted or
            // overlapping regions, and donation order is what assigns guest-node
            // identity, so a region that restarted lower would alias another node.
            for pair in regions.windows(2) {
                let (prev_gpa, prev_size, _) = pair[0];
                let (next_gpa, _, _) = pair[1];
                let prev_end = prev_gpa.0 + prev_size as u64;
                prop_assert!(next_gpa.0 > prev_gpa.0);
                let contiguous = next_gpa.0 == prev_end;
                let crosses_hole =
                    prev_end == EnclaveVm::PCIE_MMIO_BASE && next_gpa.0 == EnclaveVm::HIGH_RAM_BASE;
                prop_assert!(contiguous || crosses_hole);
            }

            // Nodes are laid out in order, each contributing its exact size, so a
            // node's regions are consecutive rather than interleaved.
            let mut tag_order: Vec<u16> = regions.iter().map(|&(_, _, t)| t).collect();
            tag_order.dedup();
            let expected: Vec<u16> = nodes.iter().map(|n| n.parent_numa).collect();
            prop_assert_eq!(tag_order, expected);
            for node in &nodes {
                let donated: usize = regions
                    .iter()
                    .filter(|&&(_, _, tag)| tag == node.parent_numa)
                    .map(|&(_, size, _)| size)
                    .sum();
                prop_assert_eq!(donated, mib_to_bytes(node.mem_size_mib));
            }
        }
    }

    fn numa_node(parent_numa: u16, vcpu_count: u16, mem_size_mib: usize) -> EnclaveNumaNode {
        EnclaveNumaNode {
            parent_numa,
            vcpu_count,
            mem_size_mib,
        }
    }

    #[test]
    fn test_split_ram_regions_single_node_pins_parent() {
        // A one-entry config pins the whole (hole-split) layout to that node.
        let size = 256 * 1024 * 1024;
        let nodes = vec![numa_node(1, 2, 256)];
        let regions = EnclaveVm::split_ram_regions(&nodes);
        assert_eq!(
            regions,
            vec![(GuestAddress(EnclaveVm::ENCLAVE_RAM_BASE), size, 1)]
        );
    }

    #[test]
    fn test_split_ram_regions_node_split_around_hole() {
        // Node 0 crosses the PCI hole: it splits into a low + high chunk sharing
        // its parent node; node 1 follows in high RAM.
        let low = EnclaveVm::LOW_RAM_MAX_SIZE;
        let overflow = 128 * 1024 * 1024;
        let node0_mib = (low + overflow) / (1024 * 1024);
        let node1_mib = 128;
        let nodes = vec![numa_node(0, 2, node0_mib), numa_node(1, 2, node1_mib)];
        let regions = EnclaveVm::split_ram_regions(&nodes);
        // Node 1's base is the running sum of node 0's chunks, so it must follow
        // node 0's overflow in high RAM rather than restarting at the RAM base.
        assert_eq!(
            regions,
            vec![
                (GuestAddress(EnclaveVm::ENCLAVE_RAM_BASE), low, 0),
                (GuestAddress(EnclaveVm::HIGH_RAM_BASE), overflow, 0),
                (
                    GuestAddress(EnclaveVm::HIGH_RAM_BASE + overflow as u64),
                    mib_to_bytes(node1_mib),
                    1,
                ),
            ]
        );
    }

    #[test]
    fn test_split_ram_regions_single_node_split_stays_pinned() {
        // A single node larger than the hole still splits, and BOTH chunks keep
        // the requested parent node -- otherwise the overflow half would be placed
        // by the kernel's default policy instead of where the config asked.
        let low = EnclaveVm::LOW_RAM_MAX_SIZE;
        let overflow = 128 * 1024 * 1024;
        let mib = (low + overflow) / (1024 * 1024);
        let nodes = vec![numa_node(1, 2, mib)];
        let regions = EnclaveVm::split_ram_regions(&nodes);
        assert_eq!(
            regions,
            vec![
                (GuestAddress(EnclaveVm::ENCLAVE_RAM_BASE), low, 1),
                (GuestAddress(EnclaveVm::HIGH_RAM_BASE), overflow, 1),
            ]
        );
    }

    #[test]
    fn test_split_ram_regions_at_hole_boundary() {
        // Exactly LOW_RAM_MAX_SIZE fills low RAM with nothing left over, so the
        // hole is never crossed and no high-RAM region is emitted; one MiB more
        // spills a single region into high RAM. (The sub-MiB `>=` vs `>`
        // transition is pinned directly in test_gpa_chunk_for_offset_boundary,
        // since a node's size is expressed in MiB.)
        let low = EnclaveVm::LOW_RAM_MAX_SIZE;
        let low_mib = low / (1024 * 1024);
        assert_eq!(
            EnclaveVm::split_ram_regions(&[numa_node(0, 1, low_mib)]),
            vec![(GuestAddress(EnclaveVm::ENCLAVE_RAM_BASE), low, 0)]
        );
        assert_eq!(
            EnclaveVm::split_ram_regions(&[numa_node(0, 1, low_mib - 1)]),
            vec![(
                GuestAddress(EnclaveVm::ENCLAVE_RAM_BASE),
                low - 1024 * 1024,
                0
            )]
        );
        assert_eq!(
            EnclaveVm::split_ram_regions(&[numa_node(0, 1, low_mib + 1)]),
            vec![
                (GuestAddress(EnclaveVm::ENCLAVE_RAM_BASE), low, 0),
                (GuestAddress(EnclaveVm::HIGH_RAM_BASE), 1024 * 1024, 0),
            ]
        );
    }

    #[test]
    fn test_gpa_chunk_for_offset_boundary() {
        // The exact byte transition `split_ram_regions` can no longer express
        // (node sizes are in MiB): one byte short of the hole still yields a low
        // chunk, exactly at the hole switches to high RAM.
        let low = EnclaveVm::LOW_RAM_MAX_SIZE;
        let (gpa, chunk) = EnclaveVm::gpa_chunk_for_offset(low - 1, 1);
        assert_eq!(gpa, EnclaveVm::ENCLAVE_RAM_BASE + (low as u64 - 1));
        assert_eq!(chunk, 1);
        let (gpa, chunk) = EnclaveVm::gpa_chunk_for_offset(low, 1);
        assert_eq!(gpa, EnclaveVm::HIGH_RAM_BASE);
        assert_eq!(chunk, 1);
    }
}

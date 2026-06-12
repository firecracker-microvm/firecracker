// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Serializable state types for Firecracker v1.14 (snapshot format version 8.0.0).
//!
//! This module is the **canonical source** for types shared across all snapshot versions.
//! Older modules (v1_12, v1_10) import unchanged types from here rather than defining
//! their own copies.
//!
//! Types that are unique to v1.14 or changed from v1.12:
//! - `VirtioDeviceState`: `interrupt_status` removed (moved to `MmioTransportState`)
//! - `MmioTransportState`: gains `interrupt_status`
//! - `MMIODeviceInfo`: `irq` → `gsi`
//! - `NetState`: `rx_buffers_state` retained
//! - `BalloonStatsState`: 6 new fields
//! - `BalloonState`: gains `hinting_state`
//! - aarch64 `GicState`: gains `its_state`
//! - aarch64 `VcpuState`: gains `pvtime_ipa`
//! - `GuestMemoryRegionState`: gains `region_type` and `plugged`
//! - `ACPIDeviceManagerState`: vmgenid now mandatory, adds vmclock (x86_64)
//! - New types: `ConnectedDeviceState<T>`, `DevicesState`, `ResourceAllocator`, `PmemState`,
//!   `VirtioMemState`, `MmdsState`, `GuestRegionType`, etc.

use vm_allocator::{AddressAllocator, AllocPolicy, IdAllocator};

#[cfg(target_arch = "x86_64")]
pub(crate) mod x86_64;

#[cfg(target_arch = "aarch64")]
pub(crate) mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64::*;

#[cfg(target_arch = "x86_64")]
use crate::arch::VmState;
use crate::arch::{
    FIRST_ADDR_PAST_64BITS_MMIO, GSI_LEGACY_END, GSI_LEGACY_START, GSI_MSI_END, GSI_MSI_START,
    MEM_32BIT_DEVICES_SIZE, MEM_32BIT_DEVICES_START, MEM_64BIT_DEVICES_SIZE,
    MEM_64BIT_DEVICES_START, PAST_64BITS_MMIO_SIZE, SYSTEM_MEM_SIZE, SYSTEM_MEM_START,
};
use crate::device_manager::DevicesState;
use crate::device_manager::mmio::MMIODeviceInfo;
use crate::device_manager::pci_mngr::PciDevicesState;
#[cfg(target_arch = "aarch64")]
use crate::device_manager::persist::ConnectedLegacyState;
use crate::device_manager::persist::{
    ACPIDeviceManagerState, DeviceStates, MmdsState, VirtioDeviceState as ConnectedDeviceState,
};
use crate::devices::acpi::vmgenid::VMGENID_MEM_SIZE;
use crate::devices::virtio::balloon::device::HintingState;
use crate::devices::virtio::balloon::persist::{BalloonState, BalloonStatsState};
use crate::devices::virtio::block::persist::BlockState;
use crate::devices::virtio::block::vhost_user::persist::VhostUserBlockState;
use crate::devices::virtio::block::virtio::persist::VirtioBlockState;
use crate::devices::virtio::net::persist::NetState;
use crate::devices::virtio::persist::{MmioTransportState, VirtioDeviceState};
use crate::devices::virtio::rng::persist::EntropyState;
use crate::devices::virtio::vsock::persist::{VsockFrontendState, VsockState};
use crate::mmds::data_store::MmdsVersion;
use crate::persist::{MicrovmState, v1_12};
use crate::vstate::memory::{GuestMemoryRegionState, GuestMemoryState, GuestRegionType};
use crate::vstate::resources::ResourceAllocator;

#[derive(Debug, thiserror::Error)]
pub enum ConvertError {
    #[error("VMGenID state is missing; cannot convert snapshot (v1.12 snapshot must have VMGenID)")]
    MissingVmGenId,
    #[error("vm-allocator error during ResourceAllocator reconstruction: {0}")]
    Allocator(#[from] vm_allocator::Error),
    #[error("ResourceAllocator reconstruction failed: duplicate/invalid MMIO address 0x{0:x}")]
    DuplicateAddress(u64),
    #[error("ResourceAllocator reconstruction failed: GSI {0} out of expected range")]
    #[allow(dead_code)]
    GsiOutOfRange(u32),
}

// In v1.12 x86_64, IRQ_BASE = 5 = GSI_LEGACY_START. No conversion needed.
// This constant exists for symmetry with the aarch64 SPI_START offset.
pub const SPI_START: u32 = 0; // no-op offset for x86_64

/// Convert a v1.12 IRQ number to a v1.14 GSI number.
///
/// x86_64: IRQ_BASE (5) == GSI_LEGACY_START (5) — no transformation needed.
/// aarch64: IRQ_BASE (32) != GSI_LEGACY_START (0) — subtract SPI_START (32).
pub(crate) fn irq_to_gsi(irq: u32) -> u32 {
    irq.saturating_sub(SPI_START)
}

impl VirtioDeviceState {
    /// Convert v1.12 VirtioDeviceState → v1.14 VirtioDeviceState.
    ///
    /// With v1.14, the `interrupt_status` moves from [`VirtioDeviceState`] to
    /// [`MmioTransportState`]. That's why we don't use `From<v1_12::VirtioDeviceState>` here,
    /// so we can return `interrupt_status` separately.
    pub(crate) fn from(old_state: v1_12::VirtioDeviceState) -> (Self, u32) {
        let interrupt_status = old_state.interrupt_status;
        let new_state = VirtioDeviceState {
            device_type: old_state.device_type,
            avail_features: old_state.avail_features,
            acked_features: old_state.acked_features,
            queues: old_state.queues, /* QueueState is the same type (re-exported v1_10 → v1_12 →
                                       * v1_14) */
            activated: old_state.activated,
        };
        (new_state, interrupt_status)
    }
}

/// Convert v1.12 MmioTransportState → v1.14 MmioTransportState with interrupt_status.
impl MmioTransportState {
    pub(crate) fn from(old_state: v1_12::MmioTransportState, interrupt_status: u32) -> Self {
        MmioTransportState {
            features_select: old_state.features_select,
            acked_features_select: old_state.acked_features_select,
            queue_select: old_state.queue_select,
            device_status: old_state.device_status,
            config_generation: old_state.config_generation,
            interrupt_status,
        }
    }
}

// ───────────────────────────────────────────────────────────────────
// Changed in v1.14: irq → gsi
// ───────────────────────────────────────────────────────────────────
impl MMIODeviceInfo {
    /// Convert v1.12 MMIODeviceInfo → v1.14 MMIODeviceInfo.
    /// irq (Option<NonZeroU32>, same wire format as Option<u32>) → gsi: Option<u32>
    pub(crate) fn from(old_state: v1_12::MMIODeviceInfo) -> MMIODeviceInfo {
        MMIODeviceInfo {
            addr: old_state.addr,
            len: old_state.len,
            gsi: old_state.irq.map(irq_to_gsi),
        }
    }
}

// ───────────────────────────────────────────────────────────────────
// Block device — redefined because VirtioDeviceState changed
// ───────────────────────────────────────────────────────────────────
impl VirtioBlockState {
    pub(crate) fn from(old_state: v1_12::VirtioBlockState) -> (VirtioBlockState, u32) {
        let (virtio_state, interrupt_status) = VirtioDeviceState::from(old_state.virtio_state);
        let new = VirtioBlockState {
            id: old_state.id,
            partuuid: old_state.partuuid,
            cache_type: old_state.cache_type,
            root_device: old_state.root_device,
            disk_path: old_state.disk_path,
            virtio_state,
            rate_limiter_state: old_state.rate_limiter_state,
            file_engine_type: old_state.file_engine_type,
        };
        (new, interrupt_status)
    }
}

impl VhostUserBlockState {
    pub(crate) fn from(old_state: v1_12::VhostUserBlockState) -> (VhostUserBlockState, u32) {
        let (virtio_state, interrupt_status) = VirtioDeviceState::from(old_state.virtio_state);
        let new = VhostUserBlockState {
            id: old_state.id,
            partuuid: old_state.partuuid,
            cache_type: old_state.cache_type,
            root_device: old_state.root_device,
            socket_path: old_state.socket_path,
            vu_acked_protocol_features: old_state.vu_acked_protocol_features,
            config_space: old_state.config_space,
            virtio_state,
        };
        (new, interrupt_status)
    }
}

impl BlockState {
    pub(crate) fn from(old_state: v1_12::BlockState) -> (BlockState, u32) {
        match old_state {
            v1_12::BlockState::Virtio(b) => {
                let (new, irq) = VirtioBlockState::from(b);
                (BlockState::Virtio(new), irq)
            }
            v1_12::BlockState::VhostUser(b) => {
                let (new, irq) = VhostUserBlockState::from(b);
                (BlockState::VhostUser(new), irq)
            }
        }
    }
}

// ───────────────────────────────────────────────────────────────────
// MMDS — MmdsVersionState renamed/restructured to MmdsState
// ───────────────────────────────────────────────────────────────────
impl MmdsVersion {
    pub(crate) fn from(old_state: v1_12::MmdsVersionState) -> MmdsVersion {
        match old_state {
            v1_12::MmdsVersionState::V1 => MmdsVersion::V1,
            v1_12::MmdsVersionState::V2 => MmdsVersion::V2,
        }
    }
}

// ───────────────────────────────────────────────────────────────────
// Net device — changed: VirtioDeviceState changed; rx_buffers_state retained
// ───────────────────────────────────────────────────────────────────
impl NetState {
    pub(crate) fn from(old_state: v1_12::NetState) -> (NetState, u32) {
        let (virtio_state, interrupt_status) = VirtioDeviceState::from(old_state.virtio_state);
        let new = NetState {
            id: old_state.id,
            tap_if_name: old_state.tap_if_name,
            rx_rate_limiter_state: old_state.rx_rate_limiter_state,
            tx_rate_limiter_state: old_state.tx_rate_limiter_state,
            mmds_ns: old_state.mmds_ns,
            config_space: old_state.config_space,
            virtio_state,
            rx_buffers_state: old_state.rx_buffers_state,
        };
        (new, interrupt_status)
    }
}

// ───────────────────────────────────────────────────────────────────
// Vsock device — VsockFrontendState/VsockState redefined (VirtioDeviceState changed)
// VsockUdsState and VsockBackendState are unchanged and defined above
// ───────────────────────────────────────────────────────────────────
impl VsockState {
    pub(crate) fn from(old_state: v1_12::VsockState) -> (VsockState, u32) {
        let (virtio_state, interrupt_status) =
            VirtioDeviceState::from(old_state.frontend.virtio_state);
        let new = VsockState {
            backend: old_state.backend,
            frontend: VsockFrontendState {
                cid: old_state.frontend.cid,
                virtio_state,
            },
        };
        (new, interrupt_status)
    }
}

// ───────────────────────────────────────────────────────────────────
// Balloon device — BalloonStatsState gains 6 new fields; BalloonState gains hinting_state
// ───────────────────────────────────────────────────────────────────
impl BalloonStatsState {
    pub(crate) fn from(old_state: v1_12::BalloonStatsState) -> BalloonStatsState {
        BalloonStatsState {
            swap_in: old_state.swap_in,
            swap_out: old_state.swap_out,
            major_faults: old_state.major_faults,
            minor_faults: old_state.minor_faults,
            free_memory: old_state.free_memory,
            total_memory: old_state.total_memory,
            available_memory: old_state.available_memory,
            disk_caches: old_state.disk_caches,
            hugetlb_allocations: old_state.hugetlb_allocations,
            hugetlb_failures: old_state.hugetlb_failures,
            oom_kill: None,
            alloc_stall: None,
            async_scan: None,
            direct_scan: None,
            async_reclaim: None,
            direct_reclaim: None,
        }
    }
}

impl BalloonState {
    pub(crate) fn from(old_state: v1_12::BalloonState) -> (BalloonState, u32) {
        let (virtio_state, interrupt_status) = VirtioDeviceState::from(old_state.virtio_state);
        let new = BalloonState {
            stats_polling_interval_s: old_state.stats_polling_interval_s,
            stats_desc_index: old_state.stats_desc_index,
            latest_stats: BalloonStatsState::from(old_state.latest_stats),
            config_space: old_state.config_space,
            hinting_state: HintingState {
                host_cmd: 0,
                last_cmd_id: 0,
                guest_cmd: None,
                // Default: acknowledge on finish (matches firecracker's `default_ack_on_stop()`)
                acknowledge_on_finish: true,
            },
            virtio_state,
        };
        (new, interrupt_status)
    }
}

// ───────────────────────────────────────────────────────────────────
// Entropy device — redefined because VirtioDeviceState changed
// ───────────────────────────────────────────────────────────────────
impl EntropyState {
    pub(crate) fn from(old_state: v1_12::EntropyState) -> (EntropyState, u32) {
        let (virtio_state, interrupt_status) = VirtioDeviceState::from(old_state.virtio_state);
        let new = EntropyState {
            virtio_state,
            rate_limiter_state: old_state.rate_limiter_state,
        };
        (new, interrupt_status)
    }
}

macro_rules! convert_connected_state {
    ($old_type:ty, $new_type:ty) => {
        impl From<$old_type> for ConnectedDeviceState<$new_type> {
            fn from(old_type: $old_type) -> Self {
                let (device_state, interrupt_status) = <$new_type>::from(old_type.device_state);
                let transport_state =
                    MmioTransportState::from(old_type.transport_state, interrupt_status);
                ConnectedDeviceState {
                    device_id: old_type.device_id,
                    device_state,
                    transport_state,
                    device_info: MMIODeviceInfo::from(old_type.device_info),
                }
            }
        }
    };
}

convert_connected_state!(v1_12::ConnectedBlockState, BlockState);
convert_connected_state!(v1_12::ConnectedNetState, NetState);
convert_connected_state!(v1_12::ConnectedVsockState, VsockState);
convert_connected_state!(v1_12::ConnectedBalloonState, BalloonState);
convert_connected_state!(v1_12::ConnectedEntropyState, EntropyState);

// ───────────────────────────────────────────────────────────────────
// Device states (v1.14 layout)
// ───────────────────────────────────────────────────────────────────

impl From<v1_12::DeviceStates> for DeviceStates {
    fn from(old_state: v1_12::DeviceStates) -> Self {
        DeviceStates {
            #[cfg(target_arch = "aarch64")]
            legacy_devices: old_state
                .legacy_devices
                .into_iter()
                .map(ConnectedLegacyState::from)
                .collect(),
            block_devices: old_state
                .block_devices
                .into_iter()
                .map(ConnectedDeviceState::<BlockState>::from)
                .collect(),
            net_devices: old_state
                .net_devices
                .into_iter()
                .map(ConnectedDeviceState::<NetState>::from)
                .collect(),
            vsock_device: old_state
                .vsock_device
                .map(ConnectedDeviceState::<VsockState>::from),
            balloon_device: old_state
                .balloon_device
                .map(ConnectedDeviceState::<BalloonState>::from),
            mmds: old_state.mmds_version.map(|v| MmdsState {
                version: MmdsVersion::from(v),
                imds_compat: false,
            }),
            entropy_device: old_state
                .entropy_device
                .map(ConnectedDeviceState::<EntropyState>::from),
            // pmem and memory devices are new in v1.14, not present in v1.12
            pmem_devices: Vec::new(),
            memory_device: None,
        }
    }
}

// ───────────────────────────────────────────────────────────────────
// Memory state (v1.14: region_type and plugged added)
// ───────────────────────────────────────────────────────────────────
impl From<v1_12::GuestMemoryState> for GuestMemoryState {
    fn from(old_state: v1_12::GuestMemoryState) -> Self {
        GuestMemoryState {
            regions: old_state
                .regions
                .into_iter()
                .map(|r| GuestMemoryRegionState {
                    base_address: r.base_address,
                    size: r.size,
                    // v1.12 snapshots don't have memory hotplug, all regions are Dram
                    region_type: GuestRegionType::Dram,
                    // No slots were plugged/unplugged; Dram regions have a single slot
                    // of size == region size, so there's 1 plugged slot
                    plugged: vec![true],
                })
                .collect(),
        }
    }
}

// ───────────────────────────────────────────────────────────────────
// ResourceAllocator (new in v1.14)
// ───────────────────────────────────────────────────────────────────
impl ResourceAllocator {
    /// Reconstruct the v1.14 ResourceAllocator from v1.12 device information.
    ///
    /// In v1.12, the ResourceAllocator state wasn't persisted; in v1.14 it is.
    /// We reconstruct it by marking all allocations that were made during VM setup.
    pub(crate) fn from(
        device_states: &v1_12::DeviceStates,
        acpi_state: &v1_12::ACPIDeviceManagerState,
    ) -> Result<ResourceAllocator, ConvertError> {
        // Initialize fresh allocators matching ResourceAllocator::new()
        let mut gsi_legacy =
            IdAllocator::new(GSI_LEGACY_START, GSI_LEGACY_END).map_err(ConvertError::Allocator)?;
        let mut gsi_msi =
            IdAllocator::new(GSI_MSI_START, GSI_MSI_END).map_err(ConvertError::Allocator)?;
        let mut mmio32 = AddressAllocator::new(MEM_32BIT_DEVICES_START, MEM_32BIT_DEVICES_SIZE)
            .map_err(ConvertError::Allocator)?;

        // 64-bit MMIO space
        let mmio64_start = MEM_64BIT_DEVICES_START;
        let mmio64_size = MEM_64BIT_DEVICES_SIZE;
        let mmio64 =
            AddressAllocator::new(mmio64_start, mmio64_size).map_err(ConvertError::Allocator)?;

        // Past 64-bit MMIO space
        let past_mmio64_start = FIRST_ADDR_PAST_64BITS_MMIO;
        let past_mmio64_size = PAST_64BITS_MMIO_SIZE;
        let past_mmio64 = AddressAllocator::new(past_mmio64_start, past_mmio64_size)
            .map_err(ConvertError::Allocator)?;

        // System memory allocator
        let mut system_mem = AddressAllocator::new(SYSTEM_MEM_START, SYSTEM_MEM_SIZE)
            .map_err(ConvertError::Allocator)?;

        // Collect all used GSIs and MMIO addresses from devices
        let mut used_legacy_gsis: Vec<u32> = Vec::new();
        let mut used_msi_gsis: Vec<u32> = Vec::new();
        let mut used_mmio32_addrs: Vec<(u64, u64)> = Vec::new(); // (addr, len)

        // Helper to classify and record a device's MMIODeviceInfo.
        // On aarch64, v1.12 stores IRQ numbers starting from IRQ_BASE=32 (physical SPI),
        // while v1.14 uses 0-based GSI numbers. We convert with irq_to_gsi().
        // Also: only record MMIO addresses within the v1.14 mmio32_memory range
        // [MEM_32BIT_DEVICES_START, ...). Addresses below that (serial, RTC, early virtio
        // devices allocated from v1.12's single MMIO allocator) are not tracked by the
        // v1.14 mmio32_memory allocator and must be skipped.
        let mut record_device_info = |info: &v1_12::MMIODeviceInfo| {
            if let Some(irq) = info.irq {
                let gsi = irq_to_gsi(irq);
                if (GSI_LEGACY_START..=GSI_LEGACY_END).contains(&gsi) {
                    used_legacy_gsis.push(gsi);
                } else if (GSI_MSI_START..=GSI_MSI_END).contains(&gsi) {
                    used_msi_gsis.push(gsi);
                }
            }
            // Only record addresses within the v1.14 mmio32_memory range
            if info.addr >= MEM_32BIT_DEVICES_START {
                used_mmio32_addrs.push((info.addr, info.len));
            }
        };

        for dev in &device_states.block_devices {
            record_device_info(&dev.device_info);
        }
        for dev in &device_states.net_devices {
            record_device_info(&dev.device_info);
        }
        if let Some(dev) = &device_states.vsock_device {
            record_device_info(&dev.device_info);
        }
        if let Some(dev) = &device_states.balloon_device {
            record_device_info(&dev.device_info);
        }
        if let Some(dev) = &device_states.entropy_device {
            record_device_info(&dev.device_info);
        }

        #[cfg(target_arch = "aarch64")]
        for dev in &device_states.legacy_devices {
            record_device_info(&dev.device_info);
        }

        // Also account for VMGenID's legacy GSI.
        // v1.12 stores IRQ_BASE-based values; convert to v1.14 0-based GSI.
        if let Some(vmgenid) = &acpi_state.vmgenid {
            let gsi = irq_to_gsi(vmgenid.gsi);
            if (GSI_LEGACY_START..=GSI_LEGACY_END).contains(&gsi) {
                used_legacy_gsis.push(gsi);
            }
        }

        // Reconstruct legacy GSI allocator
        // IdAllocator allocates sequentially. To reconstruct it, we allocate IDs up to
        // max(used_ids) and free the ones we didn't use.
        if !used_legacy_gsis.is_empty() {
            let max_gsi = *used_legacy_gsis.iter().max().unwrap();
            let used_set: std::collections::HashSet<u32> =
                used_legacy_gsis.iter().cloned().collect();

            // Allocate all IDs from start to max
            let mut allocated = Vec::new();
            for id in GSI_LEGACY_START..=max_gsi {
                let got = gsi_legacy.allocate_id().map_err(ConvertError::Allocator)?;
                allocated.push(got);
                assert_eq!(got, id, "IdAllocator must allocate sequentially");
            }
            // Free the ones not in use
            for id in GSI_LEGACY_START..=max_gsi {
                if !used_set.contains(&id) {
                    gsi_legacy.free_id(id).map_err(ConvertError::Allocator)?;
                }
            }
        }

        // Reconstruct MSI GSI allocator (similarly)
        if !used_msi_gsis.is_empty() {
            let max_gsi = *used_msi_gsis.iter().max().unwrap();
            let used_set: std::collections::HashSet<u32> = used_msi_gsis.iter().cloned().collect();

            for id in GSI_MSI_START..=max_gsi {
                let got = gsi_msi.allocate_id().map_err(ConvertError::Allocator)?;
                assert_eq!(got, id);
            }
            for id in GSI_MSI_START..=max_gsi {
                if !used_set.contains(&id) {
                    gsi_msi.free_id(id).map_err(ConvertError::Allocator)?;
                }
            }
        }

        // Reconstruct 32-bit MMIO allocator
        // Each MMIO device was allocated with FirstMatch policy, so they were assigned
        // sequentially. We use ExactMatch to mark each address as used.
        for (addr, len) in &used_mmio32_addrs {
            mmio32
                .allocate(*len, 1, AllocPolicy::ExactMatch(*addr))
                .map_err(|_| ConvertError::DuplicateAddress(*addr))?;
        }

        // Reconstruct system memory allocator.
        // In v1.12, VMGenID was allocated with LastMatch (highest addr in system_memory).
        // VmClock (x86_64 only, new in v1.14) will be allocated in ACPIDeviceManagerState::from
        // using LastMatch, which will place it just below the VMGenID region.
        // We mark the VMGenID address as used here so the VmClock allocation in
        // ACPIDeviceManagerState::from gets the correct (lower) address.
        if let Some(vmgenid) = &acpi_state.vmgenid {
            system_mem
                .allocate(VMGENID_MEM_SIZE, 8, AllocPolicy::ExactMatch(vmgenid.addr))
                .map_err(|_| ConvertError::DuplicateAddress(vmgenid.addr))?;
        }

        Ok(ResourceAllocator {
            gsi_legacy_allocator: gsi_legacy,
            gsi_msi_allocator: gsi_msi,
            mmio32_memory: mmio32,
            mmio64_memory: mmio64,
            past_mmio64_memory: past_mmio64,
            system_memory: system_mem,
        })
    }
}

// ───────────────────────────────────────────────────────────────────
// Top-level MicrovmState (v1.14)
// ───────────────────────────────────────────────────────────────────
impl TryFrom<v1_12::MicrovmState> for MicrovmState {
    type Error = ConvertError;

    fn try_from(old: v1_12::MicrovmState) -> Result<MicrovmState, Self::Error> {
        // Reconstruct ResourceAllocator from device info
        let mut resource_allocator =
            ResourceAllocator::from(&old.device_states, &old.acpi_dev_state)?;

        // Convert ACPI state (also allocates VmClock from resource_allocator on x86_64)
        let acpi_state = ACPIDeviceManagerState::from(old.acpi_dev_state, &mut resource_allocator)?;

        // Convert device states
        let mmio_state = DeviceStates::from(old.device_states);

        let device_states = DevicesState {
            mmio_state,
            acpi_state,
            pci_state: PciDevicesState::default(),
        };

        // Convert VM state (embeds the reconstructed resource allocator)
        let vm_state = VmState::from(old.vm_state, resource_allocator);

        // x86_64: VcpuState is the same type in v1.12 and v1.14.
        // aarch64: VcpuState gains pvtime_ipa field, needs conversion.
        #[cfg(target_arch = "x86_64")]
        let vcpu_states = old.vcpu_states;
        #[cfg(target_arch = "aarch64")]
        let vcpu_states: Vec<VcpuState> =
            old.vcpu_states.into_iter().map(VcpuState::from).collect();

        Ok(MicrovmState {
            vm_info: old.vm_info,
            kvm_state: old.kvm_state,
            vm_state,
            vcpu_states,
            device_states,
        })
    }
}

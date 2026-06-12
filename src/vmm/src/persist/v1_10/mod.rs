// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Serializable state types for Firecracker v1.10 (snapshot format version 4.0.0).
//!
//! Types that are identical to v1.14 are imported from that module (the canonical source).
//! Types that are the same in v1.10 and v1.12 (but different from v1.14) are imported
//! from v1.12 (the canonical source for that version pair).
//! Only types that are truly v1.10-specific are defined here.
//!
//! Key differences from v1.12:
//! - `GuestMemoryRegionState` includes an `offset` field (removed in v1.11)
//! - `MMIODeviceInfo` uses `irqs: Vec<u32>` (changed to `irq: Option<u32>` in v1.11)
//! - `VmState` (both arches) has `kvm_cap_modifiers` instead of `memory`
//! - `MicrovmState` has `memory_state: GuestMemoryState` at the top level (not inside VmState)
//! - x86_64 `VcpuState.xsave` is `kvm_xsave` (changed to `Xsave` in v1.12)
//! - No `KvmState` wrapper struct

use serde::{Deserialize, Serialize};

#[cfg(target_arch = "x86_64")]
pub(crate) mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64::*;

#[cfg(target_arch = "aarch64")]
pub(crate) mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64::*;

pub use super::v1_12::{
    // ACPI device manager state (used in MicrovmState defined below)
    ACPIDeviceManagerState,
    BalloonState,
    // Device inner states (used in Connected* wrappers defined below)
    BlockState,
    EntropyState,
    // MMDS version (used in DeviceStates defined below)
    MmdsVersionState,
    // Virtio transport state (used in Connected* wrappers defined below)
    MmioTransportState,
    NetState,
    VsockState,
};
// ───────────────────────────────────────────────────────────────────
// Types identical to v1.12 — imported from that module (canonical source)
// ───────────────────────────────────────────────────────────────────
use crate::persist::VmInfo;

// ───────────────────────────────────────────────────────────────────
// MMIO device info (v1.10 uses `irqs: Vec<u32>`, changed to `irq: Option<u32>` in v1.11)
// ───────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MMIODeviceInfo {
    pub addr: u64,
    pub len: u64,
    pub irqs: Vec<u32>,
}

// ───────────────────────────────────────────────────────────────────
// Connected device state wrappers (use v1.10 MMIODeviceInfo with irqs: Vec<u32>)
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectedBlockState {
    pub device_id: String,
    pub device_state: BlockState,
    pub transport_state: MmioTransportState,
    pub device_info: MMIODeviceInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectedNetState {
    pub device_id: String,
    pub device_state: NetState,
    pub transport_state: MmioTransportState,
    pub device_info: MMIODeviceInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectedVsockState {
    pub device_id: String,
    pub device_state: VsockState,
    pub transport_state: MmioTransportState,
    pub device_info: MMIODeviceInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectedBalloonState {
    pub device_id: String,
    pub device_state: BalloonState,
    pub transport_state: MmioTransportState,
    pub device_info: MMIODeviceInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectedEntropyState {
    pub device_id: String,
    pub device_state: EntropyState,
    pub transport_state: MmioTransportState,
    pub device_info: MMIODeviceInfo,
}

// ───────────────────────────────────────────────────────────────────
// Device states (v1.10 layout)
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DeviceStates {
    #[cfg(target_arch = "aarch64")]
    pub legacy_devices: Vec<ConnectedLegacyState>,
    pub block_devices: Vec<ConnectedBlockState>,
    pub net_devices: Vec<ConnectedNetState>,
    pub vsock_device: Option<ConnectedVsockState>,
    pub balloon_device: Option<ConnectedBalloonState>,
    pub mmds_version: Option<MmdsVersionState>,
    pub entropy_device: Option<ConnectedEntropyState>,
}

// ───────────────────────────────────────────────────────────────────
// Memory state (v1.10: GuestMemoryRegionState has `offset` field)
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestMemoryRegionState {
    pub base_address: u64,
    pub size: usize,
    /// File offset into the memory snapshot file (present in v1.10, removed in v1.11)
    pub offset: u64,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestMemoryState {
    pub regions: Vec<GuestMemoryRegionState>,
}

// ───────────────────────────────────────────────────────────────────
// Top-level MicrovmState (v1.10)
// Note: `memory_state` is at this level (not inside VmState), and there is no `kvm_state`.
// The kvm_cap_modifiers field lives inside VmState.
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct MicrovmState {
    pub vm_info: VmInfo,
    pub memory_state: GuestMemoryState,
    pub vm_state: VmState,
    pub vcpu_states: Vec<VcpuState>,
    pub device_states: DeviceStates,
    pub acpi_dev_state: ACPIDeviceManagerState,
}

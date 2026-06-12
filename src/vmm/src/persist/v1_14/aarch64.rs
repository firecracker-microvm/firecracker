// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

use super::{
    ACPIDeviceManagerState, ConvertError, GuestMemoryState, MMIODeviceInfo, ResourceAllocator,
    irq_to_gsi,
};
// ───────────────────────────────────────────────────────────────────
// Re-export runtime types — v1.14 snapshot format matches the runtime format.
// These are used by v1.12 (and v1.10 via v1.12) as canonical type definitions.
// ───────────────────────────────────────────────────────────────────
pub use crate::arch::aarch64::gic::{GicRegState, GicState, GicVcpuState};
pub use crate::arch::aarch64::regs::Aarch64RegisterVec;
pub use crate::arch::aarch64::vcpu::VcpuState;
pub use crate::arch::aarch64::vm::VmState;
use crate::devices::acpi::vmgenid::VMGenIDState;
use crate::persist::v1_12;

// ───────────────────────────────────────────────────────────────────
// StaticCpuTemplate — aarch64-specific snapshot enum (same in v1.10, v1.12, v1.14)
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StaticCpuTemplate {
    V1N1,
    #[default]
    None,
}

// ───────────────────────────────────────────────────────────────────
// DeviceType — aarch64 legacy device type enum (snapshot format)
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeviceType {
    Virtio(u32),
    Serial,
    Rtc,
}

impl From<DeviceType> for crate::arch::DeviceType {
    fn from(dt: DeviceType) -> Self {
        match dt {
            DeviceType::Virtio(n) => crate::arch::DeviceType::Virtio(n),
            DeviceType::Serial => crate::arch::DeviceType::Serial,
            DeviceType::Rtc => crate::arch::DeviceType::Rtc,
        }
    }
}

// ───────────────────────────────────────────────────────────────────
// ConnectedLegacyState — convert v1.12 snapshot type to runtime type
// ───────────────────────────────────────────────────────────────────

impl From<v1_12::ConnectedLegacyState> for crate::device_manager::persist::ConnectedLegacyState {
    fn from(s: v1_12::ConnectedLegacyState) -> Self {
        crate::device_manager::persist::ConnectedLegacyState {
            type_: crate::arch::DeviceType::from(s.type_),
            device_info: MMIODeviceInfo::from(s.device_info),
        }
    }
}

// ───────────────────────────────────────────────────────────────────
// GIC state (aarch64, v1.14: adds its_state)
// GicState is the runtime type (re-exported above); conversion from v1.12 is here.
// ───────────────────────────────────────────────────────────────────

impl GicState {
    pub(crate) fn from(old_state: v1_12::GicState) -> GicState {
        GicState {
            dist: old_state.dist,
            gic_vcpu_states: old_state.gic_vcpu_states,
            its_state: None, // v1.12 had no ITS support
        }
    }
}

// ───────────────────────────────────────────────────────────────────
// vCPU state (aarch64, v1.14: gains pvtime_ipa)
// VcpuState is the runtime type (re-exported above); conversion from v1.12 is here.
// ───────────────────────────────────────────────────────────────────

impl VcpuState {
    pub(crate) fn from(old_state: v1_12::VcpuState) -> VcpuState {
        VcpuState {
            mp_state: old_state.mp_state,
            regs: old_state.regs,
            mpidr: old_state.mpidr,
            kvi: old_state.kvi,
            pvtime_ipa: None, // new in v1.14; default to None (not configured)
        }
    }
}

// ───────────────────────────────────────────────────────────────────
// ACPI device state (aarch64: no vmclock)
// ───────────────────────────────────────────────────────────────────

impl ACPIDeviceManagerState {
    pub(crate) fn from(
        s: v1_12::ACPIDeviceManagerState,
        _resource_allocator: &mut ResourceAllocator,
    ) -> Result<ACPIDeviceManagerState, ConvertError> {
        let vmgenid = s.vmgenid.ok_or(ConvertError::MissingVmGenId)?;
        Ok(ACPIDeviceManagerState {
            vmgenid: VMGenIDState {
                // v1.12 aarch64 uses IRQ_BASE=32-based numbers; v1.14 uses 0-based GSIs
                gsi: irq_to_gsi(vmgenid.gsi),
                addr: vmgenid.addr,
            },
        })
    }
}

// ───────────────────────────────────────────────────────────────────
// VM state (aarch64, v1.14: adds resource_allocator)
// VmState is the runtime type (re-exported above); conversion from v1.12 is here.
// ───────────────────────────────────────────────────────────────────

impl VmState {
    pub(crate) fn from(
        old_state: v1_12::VmState,
        resource_allocator: ResourceAllocator,
    ) -> VmState {
        VmState {
            memory: GuestMemoryState::from(old_state.memory),
            gic: GicState::from(old_state.gic),
            resource_allocator,
        }
    }
}

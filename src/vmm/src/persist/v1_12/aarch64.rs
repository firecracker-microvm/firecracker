// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use kvm_bindings::{kvm_mp_state, kvm_vcpu_init};
use serde::{Deserialize, Serialize};

use super::{GuestMemoryState, MMIODeviceInfo};
// Types that are canonical in v1_14 and unchanged through all versions
pub use crate::persist::v1_14::{
    // Register vector with custom serde
    Aarch64RegisterVec,
    // Legacy device type enum
    DeviceType,
    // GIC helper types (GicState itself changed — its_state added — so redefined in v1_14)
    GicRegState,
    GicVcpuState,
};

// ───────────────────────────────────────────────────────────────────
// aarch64 GIC types (identical to v1.10; its_state added in v1.14)
// Canonical definitions are here; v1.10 imports from this module.
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GicState {
    pub dist: Vec<GicRegState<u32>>,
    pub gic_vcpu_states: Vec<GicVcpuState>,
}

// ───────────────────────────────────────────────────────────────────
// vCPU state (aarch64, v1.10 = v1.12)
// Canonical definition is here; v1.10 imports from this module.
// Gains `pvtime_ipa` in v1.14.
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VcpuState {
    pub mp_state: kvm_mp_state,
    pub regs: Aarch64RegisterVec,
    pub mpidr: u64,
    pub kvi: kvm_vcpu_init,
}

// ───────────────────────────────────────────────────────────────────
// Changed in v1.12: memory moved into VmState; kvm_cap_modifiers → KvmState
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmState {
    pub memory: GuestMemoryState,
    pub gic: GicState,
}

// ───────────────────────────────────────────────────────────────────
// aarch64 ConnectedLegacyState uses updated MMIODeviceInfo
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectedLegacyState {
    pub type_: DeviceType,
    pub device_info: MMIODeviceInfo,
}

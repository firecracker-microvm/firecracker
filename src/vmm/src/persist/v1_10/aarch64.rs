// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

use super::MMIODeviceInfo;
use crate::cpu_config::templates::KvmCapability;
// Types that are identical in v1.10 and v1.12 — canonical definitions in v1_12.
pub use crate::persist::v1_12::{
    // aarch64 GicState is identical in v1.10 and v1.12 (gains its_state in v1.14)
    GicState,
    // aarch64 VcpuState is identical in v1.10 and v1.12 (gains pvtime_ipa in v1.14)
    VcpuState,
};
// Types that are identical across all versions — canonical definitions in v1_14.
pub use crate::persist::v1_14::DeviceType;

// ───────────────────────────────────────────────────────────────────
// aarch64 legacy device info (v1.10 layout: uses v1.10 MMIODeviceInfo with irqs: Vec<u32>)
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectedLegacyState {
    pub type_: DeviceType,
    pub device_info: MMIODeviceInfo,
}

// ───────────────────────────────────────────────────────────────────
// VM state (aarch64, v1.10)
// In v1.10, VmState holds kvm_cap_modifiers; memory_state is at MicrovmState level.
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmState {
    pub gic: GicState,
    pub kvm_cap_modifiers: Vec<KvmCapability>,
}

// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use kvm_bindings::{kvm_clock_data, kvm_irqchip, kvm_pit_state2};
use serde::{Deserialize, Serialize};

use super::{GuestMemoryState, v1_10};
use crate::arch::VcpuState;
use crate::persist::v1_14::x86_64::xsave_from_v1_10;

// ───────────────────────────────────────────────────────────────────
// Changed in v1.12: memory moved into VmState; kvm_cap_modifiers → KvmState
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmState {
    pub memory: GuestMemoryState,
    pub pitstate: kvm_pit_state2,
    pub clock: kvm_clock_data,
    pub pic_master: kvm_irqchip,
    pub pic_slave: kvm_irqchip,
    pub ioapic: kvm_irqchip,
}

// ───────────────────────────────────────────────────────────────────
// Changed in v1.12: xsave type changed from kvm_xsave → Xsave
// VcpuState is defined in v1_14 (same in v1.12 and v1.14); conversion from v1.10 is here.
// ───────────────────────────────────────────────────────────────────

impl VcpuState {
    pub(crate) fn from(old: v1_10::VcpuState) -> VcpuState {
        VcpuState {
            cpuid: old.cpuid,
            saved_msrs: old.saved_msrs,
            debug_regs: old.debug_regs,
            lapic: old.lapic,
            mp_state: old.mp_state,
            regs: old.regs,
            sregs: old.sregs,
            vcpu_events: old.vcpu_events,
            xcrs: old.xcrs,
            xsave: xsave_from_v1_10(old.xsave),
            tsc_khz: old.tsc_khz,
        }
    }
}

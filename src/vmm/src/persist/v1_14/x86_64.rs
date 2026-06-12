// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub use kvm_bindings::Xsave;
use kvm_bindings::kvm_xsave;
use vm_allocator::AllocPolicy;

use super::{ACPIDeviceManagerState, GuestMemoryState, ResourceAllocator, v1_12};
use crate::arch::VmState;
use crate::devices::acpi::generated::vmclock_abi::{
    VMCLOCK_COUNTER_INVALID, VMCLOCK_MAGIC, VMCLOCK_STATUS_UNKNOWN, vmclock_abi,
};
use crate::devices::acpi::vmclock::{VMCLOCK_SIZE, VmClockState};
use crate::persist::v1_14::ConvertError;

// ───────────────────────────────────────────────────────────────────
// ACPI device state impl (x86_64: allocates vmclock)
// ───────────────────────────────────────────────────────────────────

impl ACPIDeviceManagerState {
    pub(crate) fn from(
        s: v1_12::ACPIDeviceManagerState,
        resource_allocator: &mut ResourceAllocator,
    ) -> Result<ACPIDeviceManagerState, ConvertError> {
        let vmgenid = s.vmgenid.ok_or(ConvertError::MissingVmGenId)?;

        // Allocate VmClock from system memory using LastMatch (same as VmClock::new())
        // VmClock must be allocated after VMGenID in the system memory allocator reconstruction.
        let vmclock_addr = resource_allocator
            .system_memory
            .allocate(
                VMCLOCK_SIZE as u64,
                VMCLOCK_SIZE as u64,
                AllocPolicy::LastMatch,
            )
            .map_err(ConvertError::Allocator)?
            .start();

        let vmclock = VmClockState {
            guest_address: vmclock_addr,
            inner: vmclock_abi {
                magic: VMCLOCK_MAGIC,
                size: VMCLOCK_SIZE,
                version: 1,
                clock_status: VMCLOCK_STATUS_UNKNOWN,
                counter_id: VMCLOCK_COUNTER_INVALID,
                ..Default::default()
            },
        };

        Ok(ACPIDeviceManagerState { vmgenid, vmclock })
    }
}

// ───────────────────────────────────────────────────────────────────
// VM state (x86_64, v1.14: adds resource_allocator)
// ───────────────────────────────────────────────────────────────────
impl VmState {
    pub(crate) fn from(s: v1_12::VmState, resource_allocator: ResourceAllocator) -> VmState {
        VmState {
            memory: GuestMemoryState::from(s.memory),
            resource_allocator,
            pitstate: s.pitstate,
            clock: s.clock,
            pic_master: s.pic_master,
            pic_slave: s.pic_slave,
            ioapic: s.ioapic,
        }
    }
}

// ───────────────────────────────────────────────────────────────────
// Helper used by v1_12::VcpuState::from(v1_10::VcpuState)
// ───────────────────────────────────────────────────────────────────

/// Convert a v1.10 `kvm_xsave` into a v1.12/v1.14 `Xsave` (= `FamStructWrapper<kvm_xsave2>`).
///
/// v1.12 introduced `Xsave` to support Intel AMX extended save state (extra FAM entries).
/// A snapshot from v1.10 has no AMX state, so `len = 0` (zero FAM entries).
pub(crate) fn xsave_from_v1_10(old: kvm_xsave) -> Xsave {
    let mut xsave = Xsave::new(0).expect("failed to allocate Xsave wrapper");
    // SAFETY: We only overwrite the `xsave` sub-field, not `len`, so the
    // FamStructWrapper length invariant is preserved.
    unsafe {
        xsave.as_mut_fam_struct().xsave = old;
    }
    xsave
}

// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

#[cfg(target_arch = "x86_64")]
use std::fmt;

#[cfg(target_arch = "x86_64")]
use kvm_bindings::{
    kvm_clock_data, kvm_irqchip, kvm_pit_config, kvm_pit_state2, KVM_CLOCK_TSC_STABLE,
    KVM_IRQCHIP_IOAPIC, KVM_IRQCHIP_PIC_MASTER, KVM_IRQCHIP_PIC_SLAVE, KVM_PIT_SPEAKER_DUMMY,
};
use kvm_bindings::{kvm_userspace_memory_region, KVM_MEM_LOG_DIRTY_PAGES};
// use kvm_ioctls::{Kvm, VmFd};
use kvm_ioctls::VmFd;
use serde::{Deserialize, Serialize};

#[cfg(target_arch = "aarch64")]
use crate::arch::aarch64::gic::GICDevice;
#[cfg(target_arch = "aarch64")]
use crate::arch::aarch64::gic::GicState;
#[cfg(target_arch = "x86_64")]
use crate::utils::u64_to_usize;
use crate::vstate::kvm::Kvm;
use crate::vstate::memory::{Address, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};

/// Errors associated with the wrappers over KVM ioctls.
/// Needs `rustfmt::skip` to make multiline comments work
#[rustfmt::skip]
#[derive(Debug, PartialEq, Eq, thiserror::Error, displaydoc::Display)]
pub enum VmError {
    /// Cannot set the memory regions: {0}
    SetUserMemoryRegion(kvm_ioctls::Error),
    #[cfg(target_arch = "aarch64")]
    /// Error creating the global interrupt controller: {0}
    VmCreateGIC(crate::arch::aarch64::gic::GicError),
    /// Cannot open the VM file descriptor: {0}
    VmFd(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to get KVM vm pit state: {0}
    VmGetPit2(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to get KVM vm clock: {0}
    VmGetClock(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to get KVM vm irqchip: {0}
    VmGetIrqChip(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to set KVM vm pit state: {0}
    VmSetPit2(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to set KVM vm clock: {0}
    VmSetClock(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to set KVM vm irqchip: {0}
    VmSetIrqChip(kvm_ioctls::Error),
    /// Cannot configure the microvm: {0}
    VmSetup(kvm_ioctls::Error),
    #[cfg(target_arch = "aarch64")]
    /// Failed to save the VM's GIC state: {0}
    SaveGic(crate::arch::aarch64::gic::GicError),
    #[cfg(target_arch = "aarch64")]
    /// Failed to restore the VM's GIC state: {0}
    RestoreGic(crate::arch::aarch64::gic::GicError),
}

/// Error type for [`Vm::restore_state`]
#[allow(missing_docs)]
#[cfg(target_arch = "x86_64")]
#[derive(Debug, thiserror::Error, displaydoc::Display, PartialEq, Eq)]
pub enum RestoreStateError {
    /// Set PIT2 error: {0}
    SetPit2(kvm_ioctls::Error),
    /// Set clock error: {0}
    SetClock(kvm_ioctls::Error),
    /// Set IrqChipPicMaster error: {0}
    SetIrqChipPicMaster(kvm_ioctls::Error),
    /// Set IrqChipPicSlave error: {0}
    SetIrqChipPicSlave(kvm_ioctls::Error),
    /// Set IrqChipIoAPIC error: {0}
    SetIrqChipIoAPIC(kvm_ioctls::Error),
    /// VM error: {0}
    VmError(VmError),
}

/// Error type for [`Vm::restore_state`]
#[cfg(target_arch = "aarch64")]
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum RestoreStateError {
    /// {0}
    GicError(crate::arch::aarch64::gic::GicError),
    /// {0}
    VmError(VmError),
}

/// A wrapper around creating and using a VM.
#[derive(Debug)]
pub struct Vm {
    fd: VmFd,

    // Arm specific fields.
    // On aarch64 we need to keep around the fd obtained by creating the VGIC device.
    #[cfg(target_arch = "aarch64")]
    irqchip_handle: Option<GICDevice>,
}

/// Contains Vm functions that are usable across CPU architectures
impl Vm {
    /// Create a new `Vm` struct.
    pub fn new(kvm: &Kvm) -> Result<Self, VmError> {
        // Create fd for interacting with kvm-vm specific functions.
        let vm_fd = kvm.fd.create_vm().map_err(VmError::VmFd)?;

        #[cfg(target_arch = "aarch64")]
        {
            Ok(Vm {
                fd: vm_fd,
                irqchip_handle: None,
            })
        }

        #[cfg(target_arch = "x86_64")]
        {
            Ok(Vm { fd: vm_fd })
        }
    }

    /// Initializes the guest memory.
    pub fn memory_init(
        &self,
        guest_mem: &GuestMemoryMmap,
        track_dirty_pages: bool,
    ) -> Result<(), VmError> {
        self.set_kvm_memory_regions(guest_mem, track_dirty_pages)?;
        #[cfg(target_arch = "x86_64")]
        self.fd
            .set_tss_address(u64_to_usize(crate::arch::x86_64::layout::KVM_TSS_ADDRESS))
            .map_err(VmError::VmSetup)?;

        Ok(())
    }

    pub(crate) fn set_kvm_memory_regions(
        &self,
        guest_mem: &GuestMemoryMmap,
        track_dirty_pages: bool,
    ) -> Result<(), VmError> {
        let mut flags = 0u32;
        if track_dirty_pages {
            flags |= KVM_MEM_LOG_DIRTY_PAGES;
        }
        guest_mem
            .iter()
            .zip(0u32..)
            .try_for_each(|(region, slot)| {
                let memory_region = kvm_userspace_memory_region {
                    slot,
                    guest_phys_addr: region.start_addr().raw_value(),
                    memory_size: region.len(),
                    // It's safe to unwrap because the guest address is valid.
                    userspace_addr: guest_mem.get_host_address(region.start_addr()).unwrap() as u64,
                    flags,
                };

                // SAFETY: Safe because the fd is a valid KVM file descriptor.
                unsafe { self.fd.set_user_memory_region(memory_region) }
            })
            .map_err(VmError::SetUserMemoryRegion)?;
        Ok(())
    }

    /// Gets a reference to the kvm file descriptor owned by this VM.
    pub fn fd(&self) -> &VmFd {
        &self.fd
    }
}

#[cfg(target_arch = "aarch64")]
impl Vm {
    /// Creates the GIC (Global Interrupt Controller).
    pub fn setup_irqchip(&mut self, vcpu_count: u8) -> Result<(), VmError> {
        self.irqchip_handle = Some(
            crate::arch::aarch64::gic::create_gic(&self.fd, vcpu_count.into(), None)
                .map_err(VmError::VmCreateGIC)?,
        );
        Ok(())
    }

    /// Gets a reference to the irqchip of the VM.
    pub fn get_irqchip(&self) -> &GICDevice {
        self.irqchip_handle.as_ref().expect("IRQ chip not set")
    }

    /// Saves and returns the Kvm Vm state.
    pub fn save_state(&self, mpidrs: &[u64]) -> Result<VmState, VmError> {
        Ok(VmState {
            gic: self
                .get_irqchip()
                .save_device(mpidrs)
                .map_err(VmError::SaveGic)?,
        })
    }

    /// Restore the KVM VM state
    ///
    /// # Errors
    ///
    /// When [`GICDevice::restore_device`] errors.
    pub fn restore_state(
        &mut self,
        mpidrs: &[u64],
        state: &VmState,
    ) -> Result<(), RestoreStateError> {
        self.get_irqchip()
            .restore_device(mpidrs, &state.gic)
            .map_err(RestoreStateError::GicError)?;
        Ok(())
    }
}

/// Structure holding an general specific VM state.
#[cfg(target_arch = "aarch64")]
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct VmState {
    /// GIC state.
    pub gic: GicState,
}

#[cfg(target_arch = "x86_64")]
impl Vm {
    /// Restores the KVM VM state.
    ///
    /// # Errors
    ///
    /// When:
    /// - [`kvm_ioctls::VmFd::set_pit`] errors.
    /// - [`kvm_ioctls::VmFd::set_clock`] errors.
    /// - [`kvm_ioctls::VmFd::set_irqchip`] errors.
    /// - [`kvm_ioctls::VmFd::set_irqchip`] errors.
    /// - [`kvm_ioctls::VmFd::set_irqchip`] errors.
    pub fn restore_state(&mut self, state: &VmState) -> Result<(), RestoreStateError> {
        self.fd
            .set_pit2(&state.pitstate)
            .map_err(RestoreStateError::SetPit2)?;
        self.fd
            .set_clock(&state.clock)
            .map_err(RestoreStateError::SetClock)?;
        self.fd
            .set_irqchip(&state.pic_master)
            .map_err(RestoreStateError::SetIrqChipPicMaster)?;
        self.fd
            .set_irqchip(&state.pic_slave)
            .map_err(RestoreStateError::SetIrqChipPicSlave)?;
        self.fd
            .set_irqchip(&state.ioapic)
            .map_err(RestoreStateError::SetIrqChipIoAPIC)?;
        Ok(())
    }

    /// Creates the irq chip and an in-kernel device model for the PIT.
    pub fn setup_irqchip(&self) -> Result<(), VmError> {
        self.fd.create_irq_chip().map_err(VmError::VmSetup)?;
        // We need to enable the emulation of a dummy speaker port stub so that writing to port 0x61
        // (i.e. KVM_SPEAKER_BASE_ADDRESS) does not trigger an exit to user space.
        let pit_config = kvm_pit_config {
            flags: KVM_PIT_SPEAKER_DUMMY,
            ..Default::default()
        };
        self.fd.create_pit2(pit_config).map_err(VmError::VmSetup)
    }

    /// Saves and returns the Kvm Vm state.
    pub fn save_state(&self) -> Result<VmState, VmError> {
        let pitstate = self.fd.get_pit2().map_err(VmError::VmGetPit2)?;

        let mut clock = self.fd.get_clock().map_err(VmError::VmGetClock)?;
        // This bit is not accepted in SET_CLOCK, clear it.
        clock.flags &= !KVM_CLOCK_TSC_STABLE;

        let mut pic_master = kvm_irqchip {
            chip_id: KVM_IRQCHIP_PIC_MASTER,
            ..Default::default()
        };
        self.fd
            .get_irqchip(&mut pic_master)
            .map_err(VmError::VmGetIrqChip)?;

        let mut pic_slave = kvm_irqchip {
            chip_id: KVM_IRQCHIP_PIC_SLAVE,
            ..Default::default()
        };
        self.fd
            .get_irqchip(&mut pic_slave)
            .map_err(VmError::VmGetIrqChip)?;

        let mut ioapic = kvm_irqchip {
            chip_id: KVM_IRQCHIP_IOAPIC,
            ..Default::default()
        };
        self.fd
            .get_irqchip(&mut ioapic)
            .map_err(VmError::VmGetIrqChip)?;

        Ok(VmState {
            pitstate,
            clock,
            pic_master,
            pic_slave,
            ioapic,
        })
    }
}

#[cfg(target_arch = "x86_64")]
#[derive(Default, Deserialize, Serialize)]
/// Structure holding VM kvm state.
pub struct VmState {
    pitstate: kvm_pit_state2,
    clock: kvm_clock_data,
    // TODO: rename this field to adopt inclusive language once Linux updates it, too.
    pic_master: kvm_irqchip,
    // TODO: rename this field to adopt inclusive language once Linux updates it, too.
    pic_slave: kvm_irqchip,
    ioapic: kvm_irqchip,
}

#[cfg(target_arch = "x86_64")]
impl fmt::Debug for VmState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VmState")
            .field("pitstate", &self.pitstate)
            .field("clock", &self.clock)
            .field("pic_master", &"?")
            .field("pic_slave", &"?")
            .field("ioapic", &"?")
            .finish()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    #[cfg(target_arch = "x86_64")]
    use crate::snapshot::Snapshot;
    use crate::test_utils::single_region_mem;
    use crate::vstate::memory::GuestMemoryMmap;

    // Auxiliary function being used throughout the tests.
    pub(crate) fn setup_vm() -> (Kvm, Vm) {
        let kvm = Kvm::new(vec![]).expect("Cannot create Kvm");
        let vm = Vm::new(&kvm).expect("Cannot create new vm");
        (kvm, vm)
    }

    // Auxiliary function being used throughout the tests.
    pub(crate) fn setup_vm_with_memory(mem_size: usize) -> (Kvm, Vm, GuestMemoryMmap) {
        let (kvm, vm) = setup_vm();
        let gm = single_region_mem(mem_size);
        vm.memory_init(&gm, false).unwrap();
        (kvm, vm, gm)
    }

    #[test]
    fn test_new() {
        // Testing with a valid /dev/kvm descriptor.
        let kvm = Kvm::new(vec![]).expect("Cannot create Kvm");
        Vm::new(&kvm).unwrap();
    }

    #[test]
    fn test_vm_memory_init() {
        let (_, vm) = setup_vm();
        // Create valid memory region and test that the initialization is successful.
        let gm = single_region_mem(0x1000);
        vm.memory_init(&gm, true).unwrap();
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_vm_save_restore_state() {
        let (_, vm) = setup_vm();
        // Irqchips, clock and pitstate are not configured so trying to save state should fail.
        vm.save_state().unwrap_err();

        let (_, vm, _mem) = setup_vm_with_memory(0x1000);
        vm.setup_irqchip().unwrap();

        let vm_state = vm.save_state().unwrap();
        assert_eq!(
            vm_state.pitstate.flags | KVM_PIT_SPEAKER_DUMMY,
            KVM_PIT_SPEAKER_DUMMY
        );
        assert_eq!(vm_state.clock.flags & KVM_CLOCK_TSC_STABLE, 0);
        assert_eq!(vm_state.pic_master.chip_id, KVM_IRQCHIP_PIC_MASTER);
        assert_eq!(vm_state.pic_slave.chip_id, KVM_IRQCHIP_PIC_SLAVE);
        assert_eq!(vm_state.ioapic.chip_id, KVM_IRQCHIP_IOAPIC);

        let (_, mut vm, _mem) = setup_vm_with_memory(0x1000);
        vm.setup_irqchip().unwrap();

        vm.restore_state(&vm_state).unwrap();
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_vm_save_restore_state_bad_irqchip() {
        use kvm_bindings::KVM_NR_IRQCHIPS;

        let (_, vm, _mem) = setup_vm_with_memory(0x1000);
        vm.setup_irqchip().unwrap();
        let mut vm_state = vm.save_state().unwrap();

        let (_, mut vm, _mem) = setup_vm_with_memory(0x1000);
        vm.setup_irqchip().unwrap();

        // Try to restore an invalid PIC Master chip ID
        let orig_master_chip_id = vm_state.pic_master.chip_id;
        vm_state.pic_master.chip_id = KVM_NR_IRQCHIPS;
        vm.restore_state(&vm_state).unwrap_err();
        vm_state.pic_master.chip_id = orig_master_chip_id;

        // Try to restore an invalid PIC Slave chip ID
        let orig_slave_chip_id = vm_state.pic_slave.chip_id;
        vm_state.pic_slave.chip_id = KVM_NR_IRQCHIPS;
        vm.restore_state(&vm_state).unwrap_err();
        vm_state.pic_slave.chip_id = orig_slave_chip_id;

        // Try to restore an invalid IOPIC chip ID
        vm_state.ioapic.chip_id = KVM_NR_IRQCHIPS;
        vm.restore_state(&vm_state).unwrap_err();
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_vmstate_serde() {
        let mut snapshot_data = vec![0u8; 10000];

        let (_, mut vm, _) = setup_vm_with_memory(0x1000);
        vm.setup_irqchip().unwrap();
        let state = vm.save_state().unwrap();
        Snapshot::serialize(&mut snapshot_data.as_mut_slice(), &state).unwrap();
        let restored_state: VmState = Snapshot::deserialize(&mut snapshot_data.as_slice()).unwrap();

        vm.restore_state(&restored_state).unwrap();
    }

    #[test]
    fn test_set_kvm_memory_regions() {
        let (_, vm) = setup_vm();

        let gm = single_region_mem(0x1000);
        let res = vm.set_kvm_memory_regions(&gm, false);
        res.unwrap();

        // Trying to set a memory region with a size that is not a multiple of GUEST_PAGE_SIZE
        // will result in error.
        let gm = single_region_mem(0x10);
        let res = vm.set_kvm_memory_regions(&gm, false);
        assert_eq!(
            res.unwrap_err().to_string(),
            "Cannot set the memory regions: Invalid argument (os error 22)"
        );
    }
}

// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use kvm_bindings::{kvm_userspace_memory_region, KVM_MEM_LOG_DIRTY_PAGES};
use kvm_ioctls::VmFd;

#[cfg(target_arch = "aarch64")]
use crate::arch::aarch64::gic::GICDevice;
#[cfg(target_arch = "x86_64")]
use crate::utils::u64_to_usize;
use crate::vstate::kvm::Kvm;
use crate::vstate::memory::{Address, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};

#[cfg(target_arch = "x86_64")]
#[path = "x86_64.rs"]
mod arch;
#[cfg(target_arch = "aarch64")]
#[path = "aarch64.rs"]
mod arch;

pub use arch::{RestoreStateError, VmState};

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
    pub fn memory_init(&self, guest_mem: &GuestMemoryMmap) -> Result<(), VmError> {
        self.set_kvm_memory_regions(guest_mem)?;
        #[cfg(target_arch = "x86_64")]
        self.fd
            .set_tss_address(u64_to_usize(crate::arch::x86_64::layout::KVM_TSS_ADDRESS))
            .map_err(VmError::VmSetup)?;

        Ok(())
    }

    pub(crate) fn set_kvm_memory_regions(
        &self,
        guest_mem: &GuestMemoryMmap,
    ) -> Result<(), VmError> {
        guest_mem
            .iter()
            .zip(0u32..)
            .try_for_each(|(region, slot)| {
                let flags = if region.bitmap().is_some() {
                    KVM_MEM_LOG_DIRTY_PAGES
                } else {
                    0
                };

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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
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
        vm.memory_init(&gm).unwrap();
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
        vm.memory_init(&gm).unwrap();
    }

    #[test]
    fn test_set_kvm_memory_regions() {
        let (_, vm) = setup_vm();

        let gm = single_region_mem(0x1000);
        let res = vm.set_kvm_memory_regions(&gm);
        res.unwrap();

        // Trying to set a memory region with a size that is not a multiple of GUEST_PAGE_SIZE
        // will result in error.
        let gm = single_region_mem(0x10);
        let res = vm.set_kvm_memory_regions(&gm);
        assert_eq!(
            res.unwrap_err().to_string(),
            "Cannot set the memory regions: Invalid argument (os error 22)"
        );
    }
}

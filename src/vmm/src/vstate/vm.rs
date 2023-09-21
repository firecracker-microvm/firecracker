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
    kvm_clock_data, kvm_irqchip, kvm_pit_config, kvm_pit_state2, CpuId, MsrList,
    KVM_CLOCK_TSC_STABLE, KVM_IRQCHIP_IOAPIC, KVM_IRQCHIP_PIC_MASTER, KVM_IRQCHIP_PIC_SLAVE,
    KVM_MAX_CPUID_ENTRIES, KVM_PIT_SPEAKER_DUMMY,
};
use kvm_bindings::{kvm_userspace_memory_region, KVM_API_VERSION, KVM_MEM_LOG_DIRTY_PAGES};
use kvm_ioctls::{Kvm, VmFd};
use utils::vm_memory::{Address, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;

#[cfg(target_arch = "aarch64")]
use crate::arch::aarch64::gic::GICDevice;
#[cfg(target_arch = "aarch64")]
use crate::arch::aarch64::gic::GicState;
use crate::cpu_config::templates::KvmCapability;

/// Errors associated with the wrappers over KVM ioctls.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VmError {
    /// The host kernel reports an invalid KVM API version.
    #[error("The host kernel reports an invalid KVM API version: {0}")]
    ApiVersion(i32),
    /// Cannot initialize the KVM context due to missing capabilities.
    #[error("Missing KVM capabilities: {0:x?}")]
    Capabilities(u32),
    /// Cannot initialize the KVM context.
    #[error("{}", ({
        if .0.errno() == libc::EACCES {
            format!(
                "Error creating KVM object. [{}]\nMake sure the user \
                launching the firecracker process is configured on the /dev/kvm file's ACL.",
                .0
            )
        } else {
            format!("Error creating KVM object. [{}]", .0)
        }
    }))]
    Kvm(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to get MSR index list to save into snapshots.
    #[error("Failed to get MSR index list to save into snapshots: {0}")]
    GetMsrsToSave(#[from] crate::arch::x86_64::msr::MsrError),
    /// The number of configured slots is bigger than the maximum reported by KVM.
    #[error("The number of configured slots is bigger than the maximum reported by KVM")]
    NotEnoughMemorySlots,
    /// Cannot set the memory regions.
    #[error("Cannot set the memory regions: {0}")]
    SetUserMemoryRegion(kvm_ioctls::Error),
    #[cfg(target_arch = "aarch64")]
    /// Cannot create the global interrupt controller.
    #[error("Error creating the global interrupt controller: {0:?}")]
    VmCreateGIC(crate::arch::aarch64::gic::GicError),
    /// Cannot open the VM file descriptor.
    #[error("Cannot open the VM file descriptor: {0}")]
    VmFd(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to get KVM vm pit state.
    #[error("Failed to get KVM vm pit state: {0}")]
    VmGetPit2(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to get KVM vm clock.
    #[error("Failed to get KVM vm clock: {0}")]
    VmGetClock(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to get KVM vm irqchip.
    #[error("Failed to get KVM vm irqchip: {0}")]
    VmGetIrqChip(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to set KVM vm pit state.
    #[error("Failed to set KVM vm pit state: {0}")]
    VmSetPit2(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to set KVM vm clock.
    #[error("Failed to set KVM vm clock: {0}")]
    VmSetClock(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to set KVM vm irqchip.
    #[error("Failed to set KVM vm irqchip: {0}")]
    VmSetIrqChip(kvm_ioctls::Error),
    /// Cannot configure the microvm.
    #[error("Cannot configure the microvm: {0}")]
    VmSetup(kvm_ioctls::Error),
    #[cfg(target_arch = "aarch64")]
    /// Failed to save the VM's GIC state.
    #[error("Failed to save the VM's GIC state: {0:?}")]
    SaveGic(crate::arch::aarch64::gic::GicError),
    #[cfg(target_arch = "aarch64")]
    /// Failed to restore the VM's GIC state.
    #[error("Failed to restore the VM's GIC state: {0:?}")]
    RestoreGic(crate::arch::aarch64::gic::GicError),
}

/// Error type for [`Vm::restore_state`]
#[allow(missing_docs)]
#[cfg(target_arch = "x86_64")]
#[derive(Debug, thiserror::Error, displaydoc::Display, PartialEq, Eq)]
pub enum RestoreStateError {
    /// {0}
    SetPit2(kvm_ioctls::Error),
    /// {0}
    SetClock(kvm_ioctls::Error),
    /// {0}
    SetIrqChipPicMaster(kvm_ioctls::Error),
    /// {0}
    SetIrqChipPicSlave(kvm_ioctls::Error),
    /// {0}
    SetIrqChipIoAPIC(kvm_ioctls::Error),
    /// {0}
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
    max_memslots: usize,

    /// Additional capabilities that were specified in cpu template.
    pub kvm_cap_modifiers: Vec<KvmCapability>,

    // X86 specific fields.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    supported_cpuid: CpuId,
    #[cfg(target_arch = "x86_64")]
    msrs_to_save: MsrList,

    // Arm specific fields.
    // On aarch64 we need to keep around the fd obtained by creating the VGIC device.
    #[cfg(target_arch = "aarch64")]
    irqchip_handle: Option<GICDevice>,
}

/// Contains Vm functions that are usable across CPU architectures
impl Vm {
    /// Constructs a new `Vm` using the given `Kvm` instance.
    pub fn new(kvm_cap_modifiers: Vec<KvmCapability>) -> Result<Self, VmError> {
        let kvm = Kvm::new().map_err(VmError::Kvm)?;

        // Check that KVM has the correct version.
        // Safe to cast because this is a constant.
        #[allow(clippy::cast_possible_wrap)]
        if kvm.get_api_version() != KVM_API_VERSION as i32 {
            return Err(VmError::ApiVersion(kvm.get_api_version()));
        }

        let total_caps = Self::combine_capabilities(&kvm_cap_modifiers);
        // Check that all desired capabilities are supported.
        Self::check_capabilities(&kvm, &total_caps).map_err(VmError::Capabilities)?;

        let max_memslots = kvm.get_nr_memslots();
        // Create fd for interacting with kvm-vm specific functions.
        let vm_fd = kvm.create_vm().map_err(VmError::VmFd)?;

        #[cfg(target_arch = "aarch64")]
        {
            Ok(Vm {
                fd: vm_fd,
                max_memslots,
                kvm_cap_modifiers,
                irqchip_handle: None,
            })
        }

        #[cfg(target_arch = "x86_64")]
        {
            let supported_cpuid = kvm
                .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
                .map_err(VmError::VmFd)?;
            let msrs_to_save = crate::arch::x86_64::msr::get_msrs_to_save(&kvm)?;

            Ok(Vm {
                fd: vm_fd,
                max_memslots,
                kvm_cap_modifiers,
                supported_cpuid,
                msrs_to_save,
            })
        }
    }

    fn combine_capabilities(kvm_cap_modifiers: &[KvmCapability]) -> Vec<u32> {
        let mut total_caps = Self::DEFAULT_CAPABILITIES.to_vec();
        for modifier in kvm_cap_modifiers.iter() {
            match modifier {
                KvmCapability::Add(cap) => {
                    if !total_caps.iter().any(|c| c == cap) {
                        total_caps.push(*cap);
                    }
                }
                KvmCapability::Remove(cap) => {
                    if let Some(pos) = total_caps.iter().position(|c| c == cap) {
                        total_caps.remove(pos);
                    }
                }
            }
        }
        total_caps
    }

    fn check_capabilities(kvm: &Kvm, capabilities: &[u32]) -> Result<(), u32> {
        for cap in capabilities {
            // If capability is not supported kernel will return 0.
            if kvm.check_extension_raw(u64::from(*cap)) == 0 {
                return Err(*cap);
            }
        }
        Ok(())
    }

    /// Initializes the guest memory.
    pub fn memory_init(
        &self,
        guest_mem: &GuestMemoryMmap,
        track_dirty_pages: bool,
    ) -> Result<(), VmError> {
        if guest_mem.num_regions() > self.max_memslots {
            return Err(VmError::NotEnoughMemorySlots);
        }
        self.set_kvm_memory_regions(guest_mem, track_dirty_pages)?;
        #[cfg(target_arch = "x86_64")]
        self.fd
            .set_tss_address(crate::arch::x86_64::layout::KVM_TSS_ADDRESS as usize)
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
            .enumerate()
            .try_for_each(|(index, region)| {
                let memory_region = kvm_userspace_memory_region {
                    slot: index as u32,
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
    const DEFAULT_CAPABILITIES: [u32; 7] = [
        kvm_bindings::KVM_CAP_IOEVENTFD,
        kvm_bindings::KVM_CAP_IRQFD,
        kvm_bindings::KVM_CAP_USER_MEMORY,
        kvm_bindings::KVM_CAP_ARM_PSCI_0_2,
        kvm_bindings::KVM_CAP_DEVICE_CTRL,
        kvm_bindings::KVM_CAP_MP_STATE,
        kvm_bindings::KVM_CAP_ONE_REG,
    ];

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
            kvm_cap_modifiers: self.kvm_cap_modifiers.clone(),
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
#[derive(Debug, Default, Versionize)]
pub struct VmState {
    /// GIC state.
    pub gic: GicState,
    /// Additional capabilities that were specified in cpu template.
    #[version(start = 2, default_fn = "default_caps")]
    pub kvm_cap_modifiers: Vec<KvmCapability>,
}

#[cfg(target_arch = "x86_64")]
impl Vm {
    const DEFAULT_CAPABILITIES: [u32; 14] = [
        kvm_bindings::KVM_CAP_IRQCHIP,
        kvm_bindings::KVM_CAP_IOEVENTFD,
        kvm_bindings::KVM_CAP_IRQFD,
        kvm_bindings::KVM_CAP_USER_MEMORY,
        kvm_bindings::KVM_CAP_SET_TSS_ADDR,
        kvm_bindings::KVM_CAP_PIT2,
        kvm_bindings::KVM_CAP_PIT_STATE2,
        kvm_bindings::KVM_CAP_ADJUST_CLOCK,
        kvm_bindings::KVM_CAP_DEBUGREGS,
        kvm_bindings::KVM_CAP_MP_STATE,
        kvm_bindings::KVM_CAP_VCPU_EVENTS,
        kvm_bindings::KVM_CAP_XCRS,
        kvm_bindings::KVM_CAP_XSAVE,
        kvm_bindings::KVM_CAP_EXT_CPUID,
    ];

    /// Returns a ref to the supported `CpuId` for this Vm.
    pub fn supported_cpuid(&self) -> &CpuId {
        &self.supported_cpuid
    }

    /// Returns a ref to the list of serializable MSR indices.
    pub fn msrs_to_save(&self) -> &MsrList {
        &self.msrs_to_save
    }

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
            kvm_cap_modifiers: self.kvm_cap_modifiers.clone(),
        })
    }
}

#[cfg(target_arch = "x86_64")]
#[derive(Default, Versionize)]
/// Structure holding VM kvm state.
// NOTICE: Any changes to this structure require a snapshot version bump.
pub struct VmState {
    pitstate: kvm_pit_state2,
    clock: kvm_clock_data,
    // TODO: rename this field to adopt inclusive language once Linux updates it, too.
    pic_master: kvm_irqchip,
    // TODO: rename this field to adopt inclusive language once Linux updates it, too.
    pic_slave: kvm_irqchip,
    ioapic: kvm_irqchip,

    /// Additional capabilities that were specified in cpu template.
    #[version(start = 2, default_fn = "default_caps")]
    pub kvm_cap_modifiers: Vec<KvmCapability>,
}

impl VmState {
    fn default_caps(_: u16) -> Vec<KvmCapability> {
        Vec::default()
    }
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
    use utils::vm_memory::GuestAddress;

    use super::*;

    // Auxiliary function being used throughout the tests.
    pub(crate) fn setup_vm(mem_size: usize) -> (Vm, GuestMemoryMmap) {
        let gm = utils::vm_memory::test_utils::create_anon_guest_memory(
            &[(GuestAddress(0), mem_size)],
            false,
        )
        .unwrap();

        let vm = Vm::new(vec![]).expect("Cannot create new vm");
        assert!(vm.memory_init(&gm, false).is_ok());

        (vm, gm)
    }

    #[test]
    fn test_new() {
        // Testing with a valid /dev/kvm descriptor.
        assert!(Vm::new(vec![]).is_ok());
    }

    #[test]
    fn test_combine_capabilities() {
        // Default caps for x86_64 and aarch64 both have KVM_CAP_IOEVENTFD and don't have
        // KVM_CAP_IOMMU caps.
        let additional_capabilities = vec![
            KvmCapability::Add(kvm_bindings::KVM_CAP_IOMMU),
            KvmCapability::Remove(kvm_bindings::KVM_CAP_IOEVENTFD),
        ];

        let combined_caps = Vm::combine_capabilities(&additional_capabilities);
        assert!(combined_caps
            .iter()
            .any(|c| *c == kvm_bindings::KVM_CAP_IOMMU));
        assert!(!combined_caps
            .iter()
            .any(|c| *c == kvm_bindings::KVM_CAP_IOEVENTFD));
    }

    #[test]
    fn test_vm_memory_init() {
        let vm = Vm::new(vec![]).expect("Cannot create new vm");

        // Create valid memory region and test that the initialization is successful.
        let gm = utils::vm_memory::test_utils::create_anon_guest_memory(
            &[(GuestAddress(0), 0x1000)],
            false,
        )
        .unwrap();
        assert!(vm.memory_init(&gm, true).is_ok());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_vm_save_restore_state() {
        let vm = Vm::new(vec![]).expect("new vm failed");
        // Irqchips, clock and pitstate are not configured so trying to save state should fail.
        assert!(vm.save_state().is_err());

        let (vm, _mem) = setup_vm(0x1000);
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

        let (mut vm, _mem) = setup_vm(0x1000);
        vm.setup_irqchip().unwrap();

        assert!(vm.restore_state(&vm_state).is_ok());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_vm_save_restore_state_bad_irqchip() {
        use kvm_bindings::KVM_NR_IRQCHIPS;

        let (vm, _mem) = setup_vm(0x1000);
        vm.setup_irqchip().unwrap();
        let mut vm_state = vm.save_state().unwrap();

        let (mut vm, _mem) = setup_vm(0x1000);
        vm.setup_irqchip().unwrap();

        // Try to restore an invalid PIC Master chip ID
        let orig_master_chip_id = vm_state.pic_master.chip_id;
        vm_state.pic_master.chip_id = KVM_NR_IRQCHIPS;
        assert!(vm.restore_state(&vm_state).is_err());
        vm_state.pic_master.chip_id = orig_master_chip_id;

        // Try to restore an invalid PIC Slave chip ID
        let orig_slave_chip_id = vm_state.pic_slave.chip_id;
        vm_state.pic_slave.chip_id = KVM_NR_IRQCHIPS;
        assert!(vm.restore_state(&vm_state).is_err());
        vm_state.pic_slave.chip_id = orig_slave_chip_id;

        // Try to restore an invalid IOPIC chip ID
        vm_state.ioapic.chip_id = KVM_NR_IRQCHIPS;
        assert!(vm.restore_state(&vm_state).is_err());
    }

    #[test]
    fn test_set_kvm_memory_regions() {
        let vm = Vm::new(vec![]).expect("Cannot create new vm");

        let gm = utils::vm_memory::test_utils::create_anon_guest_memory(
            &[(GuestAddress(0), 0x1000)],
            false,
        )
        .unwrap();
        let res = vm.set_kvm_memory_regions(&gm, false);
        assert!(res.is_ok());

        // Trying to set a memory region with a size that is not a multiple of PAGE_SIZE
        // will result in error.
        let gm = utils::vm_memory::test_utils::create_guest_memory_unguarded(
            &[(GuestAddress(0), 0x10)],
            false,
        )
        .unwrap();
        let res = vm.set_kvm_memory_regions(&gm, false);
        assert_eq!(
            res.unwrap_err().to_string(),
            "Cannot set the memory regions: Invalid argument (os error 22)"
        );
    }
}

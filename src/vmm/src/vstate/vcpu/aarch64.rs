// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::fmt::{Debug, Write};

use kvm_bindings::{
    kvm_mp_state, kvm_vcpu_init, KVM_ARM_VCPU_POWER_OFF, KVM_ARM_VCPU_PSCI_0_2, KVM_ARM_VCPU_SVE,
};
use kvm_ioctls::*;
use serde::{Deserialize, Serialize};

use crate::arch::aarch64::regs::{Aarch64RegisterVec, KVM_REG_ARM64_SVE_VLS};
use crate::arch::aarch64::vcpu::{
    get_all_registers, get_all_registers_ids, get_mpidr, get_mpstate, get_registers, set_mpstate,
    set_register, setup_boot_regs, VcpuError as ArchError,
};
use crate::cpu_config::aarch64::custom_cpu_template::VcpuFeatures;
use crate::cpu_config::templates::CpuConfiguration;
use crate::logger::{error, IncMetric, METRICS};
use crate::vcpu::{VcpuConfig, VcpuError};
use crate::vstate::kvm::Kvm;
use crate::vstate::memory::{Address, GuestAddress, GuestMemoryMmap};
use crate::vstate::vcpu::VcpuEmulation;
use crate::vstate::vm::Vm;

/// Errors associated with the wrappers over KVM ioctls.
#[derive(Debug, PartialEq, Eq, thiserror::Error, displaydoc::Display)]
pub enum KvmVcpuError {
    /// Error configuring the vcpu registers: {0}
    ConfigureRegisters(ArchError),
    /// Error creating vcpu: {0}
    CreateVcpu(kvm_ioctls::Error),
    /// Failed to dump CPU configuration: {0}
    DumpCpuConfig(ArchError),
    /// Error getting the vcpu preferred target: {0}
    GetPreferredTarget(kvm_ioctls::Error),
    /// Error initializing the vcpu: {0}
    Init(kvm_ioctls::Error),
    /// Error applying template: {0}
    ApplyCpuTemplate(ArchError),
    /// Failed to restore the state of the vcpu: {0}
    RestoreState(ArchError),
    /// Failed to save the state of the vcpu: {0}
    SaveState(ArchError),
}

/// Error type for [`KvmVcpu::configure`].
pub type KvmVcpuConfigureError = KvmVcpuError;

/// A wrapper around creating and using a kvm aarch64 vcpu.
#[derive(Debug)]
pub struct KvmVcpu {
    /// Index of vcpu.
    pub index: u8,
    /// KVM vcpu fd.
    pub fd: VcpuFd,
    /// Vcpu peripherals, such as buses
    pub(super) peripherals: Peripherals,
    mpidr: u64,
    kvi: kvm_vcpu_init,
}

/// Vcpu peripherals
#[derive(Default, Debug)]
pub(super) struct Peripherals {
    /// mmio bus.
    pub mmio_bus: Option<crate::devices::Bus>,
}

impl KvmVcpu {
    /// Constructs a new kvm vcpu with arch specific functionality.
    ///
    /// # Arguments
    ///
    /// * `index` - Represents the 0-based CPU index between [0, max vcpus).
    /// * `vm` - The vm to which this vcpu will get attached.
    pub fn new(index: u8, vm: &Vm, _: &Kvm) -> Result<Self, KvmVcpuError> {
        let kvm_vcpu = vm
            .fd()
            .create_vcpu(index.into())
            .map_err(KvmVcpuError::CreateVcpu)?;

        let mut kvi = Self::default_kvi(vm.fd())?;
        // Secondary vcpus must be powered off for boot process.
        if 0 < index {
            kvi.features[0] |= 1 << KVM_ARM_VCPU_POWER_OFF;
        }

        Ok(KvmVcpu {
            index,
            fd: kvm_vcpu,
            peripherals: Default::default(),
            mpidr: 0,
            kvi,
        })
    }

    /// Gets the MPIDR register value.
    pub fn get_mpidr(&self) -> u64 {
        self.mpidr
    }

    /// Configures an aarch64 specific vcpu for booting Linux.
    ///
    /// # Arguments
    ///
    /// * `guest_mem` - The guest memory used by this microvm.
    /// * `kernel_load_addr` - Offset from `guest_mem` at which the kernel is loaded.
    /// * `vcpu_config` - The vCPU configuration.
    pub fn configure(
        &mut self,
        guest_mem: &GuestMemoryMmap,
        kernel_load_addr: GuestAddress,
        vcpu_config: &VcpuConfig,
    ) -> Result<(), KvmVcpuError> {
        for reg in vcpu_config.cpu_config.regs.iter() {
            self.fd
                .set_one_reg(reg.id, reg.as_slice())
                .map_err(|err| KvmVcpuError::ApplyCpuTemplate(ArchError::SetOneReg(reg.id, err)))?;
        }

        setup_boot_regs(
            &self.fd,
            self.index,
            kernel_load_addr.raw_value(),
            guest_mem,
        )
        .map_err(KvmVcpuError::ConfigureRegisters)?;

        self.mpidr = get_mpidr(&self.fd).map_err(KvmVcpuError::ConfigureRegisters)?;

        Ok(())
    }

    /// Initializes an aarch64 specific vcpu for booting Linux.
    ///
    /// # Arguments
    ///
    /// * `vm_fd` - The kvm `VmFd` for this microvm.
    pub fn init(&mut self, vcpu_features: &[VcpuFeatures]) -> Result<(), KvmVcpuError> {
        for feature in vcpu_features.iter() {
            let index = feature.index as usize;
            self.kvi.features[index] = feature.bitmap.apply(self.kvi.features[index]);
        }

        self.init_vcpu()?;
        self.finalize_vcpu()?;

        Ok(())
    }

    /// Creates default kvi struct based on vcpu index.
    pub fn default_kvi(vm_fd: &VmFd) -> Result<kvm_vcpu_init, KvmVcpuError> {
        let mut kvi = kvm_vcpu_init::default();
        // This reads back the kernel's preferred target type.
        vm_fd
            .get_preferred_target(&mut kvi)
            .map_err(KvmVcpuError::GetPreferredTarget)?;
        // We already checked that the capability is supported.
        kvi.features[0] |= 1 << KVM_ARM_VCPU_PSCI_0_2;

        Ok(kvi)
    }

    /// Save the KVM internal state.
    pub fn save_state(&self) -> Result<VcpuState, KvmVcpuError> {
        let mut state = VcpuState {
            mp_state: get_mpstate(&self.fd).map_err(KvmVcpuError::SaveState)?,
            ..Default::default()
        };
        get_all_registers(&self.fd, &mut state.regs).map_err(KvmVcpuError::SaveState)?;
        state.mpidr = get_mpidr(&self.fd).map_err(KvmVcpuError::SaveState)?;

        state.kvi = self.kvi;
        // We don't save power off state in a snapshot, because
        // it was only needed during uVM boot process.
        // When uVM is restored, the kernel has already passed
        // the boot state and turned secondary vcpus on.
        state.kvi.features[0] &= !(1 << KVM_ARM_VCPU_POWER_OFF);

        Ok(state)
    }

    /// Use provided state to populate KVM internal state.
    pub fn restore_state(&mut self, state: &VcpuState) -> Result<(), KvmVcpuError> {
        self.kvi = state.kvi;

        self.init_vcpu()?;

        // If KVM_REG_ARM64_SVE_VLS is present it needs to
        // be set before vcpu is finalized.
        if let Some(sve_vls_reg) = state
            .regs
            .iter()
            .find(|reg| reg.id == KVM_REG_ARM64_SVE_VLS)
        {
            set_register(&self.fd, sve_vls_reg).map_err(KvmVcpuError::RestoreState)?;
        }

        self.finalize_vcpu()?;

        // KVM_REG_ARM64_SVE_VLS needs to be skipped after vcpu is finalized.
        // If it is present it is handled in the code above.
        for reg in state
            .regs
            .iter()
            .filter(|reg| reg.id != KVM_REG_ARM64_SVE_VLS)
        {
            set_register(&self.fd, reg).map_err(KvmVcpuError::RestoreState)?;
        }
        set_mpstate(&self.fd, state.mp_state).map_err(KvmVcpuError::RestoreState)?;
        Ok(())
    }

    /// Dumps CPU configuration.
    pub fn dump_cpu_config(&self) -> Result<CpuConfiguration, KvmVcpuError> {
        let reg_list = get_all_registers_ids(&self.fd).map_err(KvmVcpuError::DumpCpuConfig)?;

        let mut regs = Aarch64RegisterVec::default();
        get_registers(&self.fd, &reg_list, &mut regs).map_err(KvmVcpuError::DumpCpuConfig)?;

        Ok(CpuConfiguration { regs })
    }
    /// Initializes internal vcpufd.
    fn init_vcpu(&self) -> Result<(), KvmVcpuError> {
        self.fd.vcpu_init(&self.kvi).map_err(KvmVcpuError::Init)?;
        Ok(())
    }

    /// Checks for SVE feature and calls `vcpu_finalize` if
    /// it is enabled.
    fn finalize_vcpu(&self) -> Result<(), KvmVcpuError> {
        if (self.kvi.features[0] & (1 << KVM_ARM_VCPU_SVE)) != 0 {
            // KVM_ARM_VCPU_SVE has value 4 so casting to i32 is safe.
            #[allow(clippy::cast_possible_wrap)]
            let feature = KVM_ARM_VCPU_SVE as i32;
            self.fd.vcpu_finalize(&feature).unwrap();
        }
        Ok(())
    }
}

impl Peripherals {
    /// Runs the vCPU in KVM context and handles the kvm exit reason.
    ///
    /// Returns error or enum specifying whether emulation was handled or interrupted.
    pub fn run_arch_emulation(&self, exit: VcpuExit) -> Result<VcpuEmulation, VcpuError> {
        METRICS.vcpu.failures.inc();
        // TODO: Are we sure we want to finish running a vcpu upon
        // receiving a vm exit that is not necessarily an error?
        error!("Unexpected exit reason on vcpu run: {:?}", exit);
        Err(VcpuError::UnhandledKvmExit(format!("{:?}", exit)))
    }
}

/// Structure holding VCPU kvm state.
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct VcpuState {
    /// Multiprocessing state.
    pub mp_state: kvm_mp_state,
    /// Vcpu registers.
    pub regs: Aarch64RegisterVec,
    /// We will be using the mpidr for passing it to the VmState.
    /// The VmState will give this away for saving restoring the icc and redistributor
    /// registers.
    pub mpidr: u64,
    /// kvi states for vcpu initialization.
    pub kvi: kvm_vcpu_init,
}

impl Debug for VcpuState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "kvm_mp_state: {:#x}", self.mp_state.mp_state)?;
        writeln!(f, "mpidr: {:#x}", self.mpidr)?;
        for reg in self.regs.iter() {
            writeln!(
                f,
                "{:#x} 0x{}",
                reg.id,
                reg.as_slice()
                    .iter()
                    .rev()
                    .fold(String::new(), |mut output, b| {
                        let _ = write!(output, "{b:x}");
                        output
                    })
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]
    use std::os::unix::io::AsRawFd;

    use kvm_bindings::{KVM_ARM_VCPU_PSCI_0_2, KVM_REG_SIZE_U64};

    use super::*;
    use crate::arch::aarch64::regs::Aarch64RegisterRef;
    use crate::cpu_config::aarch64::CpuConfiguration;
    use crate::cpu_config::templates::RegisterValueFilter;
    use crate::vcpu::VcpuConfig;
    use crate::vstate::kvm::Kvm;
    use crate::vstate::memory::GuestMemoryMmap;
    use crate::vstate::vm::tests::setup_vm_with_memory;
    use crate::vstate::vm::Vm;

    fn setup_vcpu(mem_size: usize) -> (Kvm, Vm, KvmVcpu, GuestMemoryMmap) {
        let (kvm, mut vm, vm_mem) = setup_vm_with_memory(mem_size);
        let mut vcpu = KvmVcpu::new(0, &vm, &kvm).unwrap();
        vcpu.init(&[]).unwrap();
        vm.setup_irqchip(1).unwrap();

        (kvm, vm, vcpu, vm_mem)
    }

    #[test]
    fn test_create_vcpu() {
        let (kvm, vm, _) = setup_vm_with_memory(0x1000);

        unsafe { libc::close(vm.fd().as_raw_fd()) };

        let err = KvmVcpu::new(0, &vm, &kvm);
        assert_eq!(
            err.err().unwrap().to_string(),
            "Error creating vcpu: Bad file descriptor (os error 9)".to_string()
        );

        // dropping vm would double close the gic fd, so leak it
        std::mem::forget(vm);
    }

    #[test]
    fn test_configure_vcpu() {
        let (_, _, mut vcpu, vm_mem) = setup_vcpu(0x10000);

        let vcpu_config = VcpuConfig {
            vcpu_count: 1,
            smt: false,
            cpu_config: CpuConfiguration::default(),
        };
        vcpu.configure(
            &vm_mem,
            GuestAddress(crate::arch::get_kernel_start()),
            &vcpu_config,
        )
        .unwrap();

        unsafe { libc::close(vcpu.fd.as_raw_fd()) };

        let err = vcpu.configure(
            &vm_mem,
            GuestAddress(crate::arch::get_kernel_start()),
            &vcpu_config,
        );
        assert_eq!(
            err.unwrap_err(),
            KvmVcpuError::ConfigureRegisters(ArchError::SetOneReg(
                0x6030000000100042,
                kvm_ioctls::Error::new(9)
            ))
        );

        // dropping vcpu would double close the gic fd, so leak it
        std::mem::forget(vcpu);
    }

    #[test]
    fn test_init_vcpu() {
        let (kvm, mut vm, _) = setup_vm_with_memory(0x1000);
        let mut vcpu = KvmVcpu::new(0, &vm, &kvm).unwrap();
        vm.setup_irqchip(1).unwrap();

        // KVM_ARM_VCPU_PSCI_0_2 is set by default.
        // we check if we can remove it.
        let vcpu_features = vec![VcpuFeatures {
            index: 0,
            bitmap: RegisterValueFilter {
                filter: 1 << KVM_ARM_VCPU_PSCI_0_2,
                value: 0,
            },
        }];
        vcpu.init(&vcpu_features).unwrap();
        assert!((vcpu.kvi.features[0] & (1 << KVM_ARM_VCPU_PSCI_0_2)) == 0)
    }

    #[test]
    fn test_vcpu_save_restore_state() {
        let (kvm, mut vm, _) = setup_vm_with_memory(0x1000);
        let mut vcpu = KvmVcpu::new(0, &vm, &kvm).unwrap();
        vm.setup_irqchip(1).unwrap();

        // Calling KVM_GET_REGLIST before KVM_VCPU_INIT will result in error.
        let res = vcpu.save_state();
        assert!(matches!(
            res.unwrap_err(),
            KvmVcpuError::SaveState(ArchError::GetRegList(_))
        ));

        // Try to restore the register using a faulty state.
        let mut faulty_vcpu_state = VcpuState::default();

        // Try faulty kvi state
        let res = vcpu.restore_state(&faulty_vcpu_state);
        assert!(matches!(res.unwrap_err(), KvmVcpuError::Init(_)));

        // Try faulty vcpu regs
        faulty_vcpu_state.kvi = KvmVcpu::default_kvi(vm.fd()).unwrap();
        let mut regs = Aarch64RegisterVec::default();
        let mut reg = Aarch64RegisterRef::new(KVM_REG_SIZE_U64, &[0; 8]);
        reg.id = 0;
        regs.push(reg);
        faulty_vcpu_state.regs = regs;
        let res = vcpu.restore_state(&faulty_vcpu_state);
        assert!(matches!(
            res.unwrap_err(),
            KvmVcpuError::RestoreState(ArchError::SetOneReg(0, _))
        ));

        vcpu.init(&[]).unwrap();
        let state = vcpu.save_state().expect("Cannot save state of vcpu");
        assert!(!state.regs.is_empty());
        vcpu.restore_state(&state)
            .expect("Cannot restore state of vcpu");
    }

    #[test]
    fn test_dump_cpu_config_before_init() {
        // Test `dump_cpu_config()` before `KVM_VCPU_INIT`.
        //
        // This should fail with ENOEXEC.
        // https://elixir.bootlin.com/linux/v5.10.176/source/arch/arm64/kvm/arm.c#L1165
        let (kvm, mut vm, _) = setup_vm_with_memory(0x1000);
        let vcpu = KvmVcpu::new(0, &vm, &kvm).unwrap();
        vm.setup_irqchip(1).unwrap();

        vcpu.dump_cpu_config().unwrap_err();
    }

    #[test]
    fn test_dump_cpu_config_after_init() {
        // Test `dump_cpu_config()` after `KVM_VCPU_INIT`.
        let (kvm, mut vm, _) = setup_vm_with_memory(0x1000);
        let mut vcpu = KvmVcpu::new(0, &vm, &kvm).unwrap();
        vm.setup_irqchip(1).unwrap();
        vcpu.init(&[]).unwrap();

        vcpu.dump_cpu_config().unwrap();
    }

    #[test]
    fn test_setup_non_boot_vcpu() {
        let (kvm, vm, _) = setup_vm_with_memory(0x1000);
        let mut vcpu1 = KvmVcpu::new(0, &vm, &kvm).unwrap();
        vcpu1.init(&[]).unwrap();
        let mut vcpu2 = KvmVcpu::new(1, &vm, &kvm).unwrap();
        vcpu2.init(&[]).unwrap();
    }

    #[test]
    fn test_get_valid_regs() {
        // Test `get_regs()` with valid register IDs.
        // - X0: 0x6030 0000 0010 0000
        // - X1: 0x6030 0000 0010 0002
        let (_, _, vcpu, _) = setup_vcpu(0x10000);
        let reg_list = Vec::<u64>::from([0x6030000000100000, 0x6030000000100002]);
        get_registers(&vcpu.fd, &reg_list, &mut Aarch64RegisterVec::default()).unwrap();
    }

    #[test]
    fn test_get_invalid_regs() {
        // Test `get_regs()` with invalid register IDs.
        let (_, _, vcpu, _) = setup_vcpu(0x10000);
        let reg_list = Vec::<u64>::from([0x6030000000100001, 0x6030000000100003]);
        get_registers(&vcpu.fd, &reg_list, &mut Aarch64RegisterVec::default()).unwrap_err();
    }
}

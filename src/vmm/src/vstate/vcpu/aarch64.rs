// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use kvm_bindings::*;
use kvm_ioctls::*;
use utils::vm_memory::{Address, GuestAddress, GuestMemoryMmap};
use versionize::{VersionMap, Versionize, VersionizeError, VersionizeResult};
use versionize_derive::Versionize;

use crate::arch::aarch64::regs::{
    arm64_core_reg_id, offset__of, Aarch64RegisterOld, Aarch64RegisterRef, Aarch64RegisterVec,
    KVM_REG_ARM_TIMER_CNT,
};
use crate::arch::aarch64::vcpu::{
    get_all_registers, get_all_registers_ids, get_mpidr, get_mpstate, get_registers, set_mpstate,
    set_registers, setup_boot_regs, VcpuError as ArchError,
};
use crate::cpu_config::aarch64::custom_cpu_template::VcpuFeatures;
use crate::cpu_config::templates::CpuConfiguration;
use crate::logger::{error, IncMetric, METRICS};
use crate::vcpu::{VcpuConfig, VcpuError};
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
    /// Mmio bus.
    pub mmio_bus: Option<crate::devices::Bus>,
    mpidr: u64,
    kvi: Option<kvm_bindings::kvm_vcpu_init>,
}

impl KvmVcpu {
    /// Constructs a new kvm vcpu with arch specific functionality.
    ///
    /// # Arguments
    ///
    /// * `index` - Represents the 0-based CPU index between [0, max vcpus).
    /// * `vm` - The vm to which this vcpu will get attached.
    pub fn new(index: u8, vm: &Vm) -> Result<Self, KvmVcpuError> {
        let kvm_vcpu = vm
            .fd()
            .create_vcpu(index.into())
            .map_err(KvmVcpuError::CreateVcpu)?;

        Ok(KvmVcpu {
            index,
            fd: kvm_vcpu,
            mmio_bus: None,
            mpidr: 0,
            kvi: None,
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
    pub fn init(
        &mut self,
        vm_fd: &VmFd,
        vcpu_features: &[VcpuFeatures],
    ) -> Result<(), KvmVcpuError> {
        let mut kvi = Self::default_kvi(vm_fd, self.index)?;

        for feature in vcpu_features.iter() {
            let index = feature.index as usize;
            kvi.features[index] = feature.bitmap.apply(kvi.features[index]);
        }

        self.init_vcpu_fd(&kvi)?;

        self.kvi = if !vcpu_features.is_empty() {
            Some(kvi)
        } else {
            None
        };

        Ok(())
    }

    /// Creates default kvi struct based on vcpu index.
    pub fn default_kvi(
        vm_fd: &VmFd,
        index: u8,
    ) -> Result<kvm_bindings::kvm_vcpu_init, KvmVcpuError> {
        let mut kvi: kvm_bindings::kvm_vcpu_init = kvm_bindings::kvm_vcpu_init::default();
        // This reads back the kernel's preferred target type.
        vm_fd
            .get_preferred_target(&mut kvi)
            .map_err(KvmVcpuError::GetPreferredTarget)?;
        // We already checked that the capability is supported.
        kvi.features[0] |= 1 << kvm_bindings::KVM_ARM_VCPU_PSCI_0_2;

        // Non-boot cpus are powered off initially.
        if index > 0 {
            kvi.features[0] |= 1 << kvm_bindings::KVM_ARM_VCPU_POWER_OFF;
        }

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
        Ok(state)
    }

    /// Use provided state to populate KVM internal state.
    pub fn restore_state(&mut self, vm_fd: &VmFd, state: &VcpuState) -> Result<(), KvmVcpuError> {
        let kvi = match state.kvi {
            Some(kvi) => kvi,
            None => Self::default_kvi(vm_fd, self.index)?,
        };

        self.init_vcpu_fd(&kvi)?;

        self.kvi = state.kvi;
        set_registers(&self.fd, &state.regs).map_err(KvmVcpuError::RestoreState)?;
        set_mpstate(&self.fd, state.mp_state).map_err(KvmVcpuError::RestoreState)?;
        Ok(())
    }

    /// Dumps CPU configuration.
    pub fn dump_cpu_config(&self) -> Result<CpuConfiguration, KvmVcpuError> {
        let mut reg_list = get_all_registers_ids(&self.fd).map_err(KvmVcpuError::DumpCpuConfig)?;

        let kvm_reg_pc = {
            let kreg_off = offset__of!(kvm_regs, regs);
            let pc_off = offset__of!(user_pt_regs, pc) + kreg_off;
            arm64_core_reg_id!(KVM_REG_SIZE_U64, pc_off)
        };

        // KVM_REG_ARM_TIMER_CNT should be removed, because it depends on the elapsed time and
        // the dumped CPU config is used to create custom CPU templates to modify CPU features
        // exposed to guests or ot detect CPU configuration changes caused by firecracker/KVM/
        // BIOS.
        // The value of program counter (PC) is determined by the given kernel image. It should not
        // be overwritten by a custom CPU template and does not need to be tracked in a fingerprint
        // file.
        reg_list.retain(|&reg_id| reg_id != KVM_REG_ARM_TIMER_CNT && reg_id != kvm_reg_pc);

        let mut regs = Aarch64RegisterVec::default();
        get_registers(&self.fd, &reg_list, &mut regs).map_err(KvmVcpuError::DumpCpuConfig)?;

        Ok(CpuConfiguration { regs })
    }

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

    /// Initializes internal vcpufd.
    /// Does additional check for SVE and calls `vcpu_finalize` if
    /// SVE is enabled.
    fn init_vcpu_fd(&self, kvi: &kvm_bindings::kvm_vcpu_init) -> Result<(), KvmVcpuError> {
        self.fd.vcpu_init(kvi).map_err(KvmVcpuError::Init)?;
        if (kvi.features[0] & (1 << kvm_bindings::KVM_ARM_VCPU_SVE)) != 0 {
            // KVM_ARM_VCPU_SVE has value 4 so casting to i32 is safe.
            #[allow(clippy::cast_possible_wrap)]
            let feature = kvm_bindings::KVM_ARM_VCPU_SVE as i32;
            self.fd.vcpu_finalize(&feature).unwrap();
        }
        Ok(())
    }
}

/// Structure holding VCPU kvm state.
#[derive(Debug, Default, Clone, Versionize)]
pub struct VcpuState {
    /// Multiprocessing state.
    pub mp_state: kvm_bindings::kvm_mp_state,
    /// Old representation of Vcpu registers.
    #[version(end = 2, default_fn = "default_old_regs")]
    pub old_regs: Vec<Aarch64RegisterOld>,
    /// Vcpu registers.
    #[version(start = 2, de_fn = "de_regs", ser_fn = "ser_regs")]
    pub regs: Aarch64RegisterVec,
    /// We will be using the mpidr for passing it to the VmState.
    /// The VmState will give this away for saving restoring the icc and redistributor
    /// registers.
    pub mpidr: u64,
    /// kvi states for vcpu initialization.
    /// If None then use `default_kvi` to obtain
    /// kvi.
    #[version(start = 2, default_fn = "default_kvi")]
    pub kvi: Option<kvm_bindings::kvm_vcpu_init>,
}

impl VcpuState {
    fn default_old_regs(_: u16) -> Vec<Aarch64RegisterOld> {
        Vec::default()
    }

    fn default_kvi(_: u16) -> Option<kvm_bindings::kvm_vcpu_init> {
        None
    }

    fn de_regs(&mut self, _source_version: u16) -> VersionizeResult<()> {
        let mut regs = Aarch64RegisterVec::default();
        for reg in self.old_regs.iter() {
            let reg_ref: Aarch64RegisterRef = reg
                .try_into()
                .map_err(|e: &str| VersionizeError::Deserialize(e.into()))?;
            regs.push(reg_ref);
        }
        self.regs = regs;
        Ok(())
    }

    fn ser_regs(&mut self, _target_version: u16) -> VersionizeResult<()> {
        self.old_regs = self
            .regs
            .iter()
            .map(TryInto::try_into)
            .collect::<Result<_, _>>()
            .map_err(|e: &str| VersionizeError::Serialize(e.into()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]
    use std::os::unix::io::AsRawFd;

    use kvm_bindings::KVM_REG_SIZE_U64;
    use utils::vm_memory::GuestMemoryMmap;

    use super::*;
    use crate::arch::aarch64::regs::Aarch64RegisterRef;
    use crate::cpu_config::aarch64::CpuConfiguration;
    use crate::cpu_config::templates::RegisterValueFilter;
    use crate::vcpu::VcpuConfig;
    use crate::vstate::vm::tests::setup_vm;
    use crate::vstate::vm::Vm;

    fn setup_vcpu(mem_size: usize) -> (Vm, KvmVcpu, GuestMemoryMmap) {
        let (mut vm, vm_mem) = setup_vm(mem_size);
        let mut vcpu = KvmVcpu::new(0, &vm).unwrap();
        vcpu.init(vm.fd(), &[]).unwrap();
        vm.setup_irqchip(1).unwrap();

        (vm, vcpu, vm_mem)
    }

    #[test]
    fn test_create_vcpu() {
        let (vm, _) = setup_vm(0x1000);

        unsafe { libc::close(vm.fd().as_raw_fd()) };

        let err = KvmVcpu::new(0, &vm);
        assert!(err.is_err());
        assert_eq!(
            err.err().unwrap().to_string(),
            "Error creating vcpu: Bad file descriptor (os error 9)".to_string()
        );
    }

    #[test]
    fn test_configure_vcpu() {
        let (_vm, mut vcpu, vm_mem) = setup_vcpu(0x10000);

        let vcpu_config = VcpuConfig {
            vcpu_count: 1,
            smt: false,
            cpu_config: CpuConfiguration::default(),
        };
        assert!(vcpu
            .configure(
                &vm_mem,
                GuestAddress(crate::arch::get_kernel_start()),
                &vcpu_config,
            )
            .is_ok());

        unsafe { libc::close(vcpu.fd.as_raw_fd()) };

        let err = vcpu.configure(
            &vm_mem,
            GuestAddress(crate::arch::get_kernel_start()),
            &vcpu_config,
        );
        assert!(err.is_err());
        assert_eq!(
            err.unwrap_err(),
            KvmVcpuError::ConfigureRegisters(ArchError::SetOneReg(
                0x6030000000100042,
                kvm_ioctls::Error::new(9)
            ))
        );
    }

    #[test]
    fn test_init_vcpu() {
        let (mut vm, _vm_mem) = setup_vm(0x1000);
        let mut vcpu = KvmVcpu::new(0, &vm).unwrap();
        vm.setup_irqchip(1).unwrap();

        // KVM_ARM_VCPU_PSCI_0_2 is set by default.
        // we check if we can remove it.
        let vcpu_features = vec![VcpuFeatures {
            index: 0,
            bitmap: RegisterValueFilter {
                filter: 1 << kvm_bindings::KVM_ARM_VCPU_PSCI_0_2,
                value: 0,
            },
        }];
        vcpu.init(vm.fd(), &vcpu_features).unwrap();

        // Because vcpu_features vector is not empty,
        // kvi field should be non empty as well.
        let vcpu_kvi = vcpu.kvi.unwrap();
        assert!((vcpu_kvi.features[0] & (1 << kvm_bindings::KVM_ARM_VCPU_PSCI_0_2)) == 0)
    }

    #[test]
    fn test_faulty_init_vcpu() {
        let (vm, mut vcpu, _) = setup_vcpu(0x10000);
        unsafe { libc::close(vm.fd().as_raw_fd()) };
        let err = vcpu.init(vm.fd(), &[]);
        assert!(err.is_err());
        assert_eq!(
            err.err().unwrap().to_string(),
            "Error getting the vcpu preferred target: Bad file descriptor (os error 9)".to_string()
        );
    }

    #[test]
    fn test_vcpu_save_restore_state() {
        let (mut vm, _vm_mem) = setup_vm(0x1000);
        let mut vcpu = KvmVcpu::new(0, &vm).unwrap();
        vm.setup_irqchip(1).unwrap();

        // Calling KVM_GET_REGLIST before KVM_VCPU_INIT will result in error.
        let res = vcpu.save_state();
        assert!(res.is_err());
        assert!(matches!(
            res.unwrap_err(),
            KvmVcpuError::SaveState(ArchError::GetRegList(_))
        ));

        // Try to restore the register using a faulty state.
        let mut regs = Aarch64RegisterVec::default();
        let mut reg = Aarch64RegisterRef::new(KVM_REG_SIZE_U64, &[0; 8]);
        reg.id = 0;
        regs.push(reg);
        let faulty_vcpu_state = VcpuState {
            regs,
            ..Default::default()
        };
        let res = vcpu.restore_state(vm.fd(), &faulty_vcpu_state);
        assert!(res.is_err());
        assert!(matches!(
            res.unwrap_err(),
            KvmVcpuError::RestoreState(ArchError::SetOneReg(0, _))
        ));

        vcpu.init(vm.fd(), &[]).unwrap();
        let state = vcpu.save_state().expect("Cannot save state of vcpu");
        assert!(!state.regs.is_empty());
        vcpu.restore_state(vm.fd(), &state)
            .expect("Cannot restore state of vcpu");
    }

    #[test]
    fn test_dump_cpu_config_before_init() {
        // Test `dump_cpu_config()` before `KVM_VCPU_INIT`.
        //
        // This should fail with ENOEXEC.
        // https://elixir.bootlin.com/linux/v5.10.176/source/arch/arm64/kvm/arm.c#L1165
        let (mut vm, _vm_mem) = setup_vm(0x1000);
        let vcpu = KvmVcpu::new(0, &vm).unwrap();
        vm.setup_irqchip(1).unwrap();

        assert!(vcpu.dump_cpu_config().is_err());
    }

    #[test]
    fn test_dump_cpu_config_after_init() {
        // Test `dump_cpu_config()` after `KVM_VCPU_INIT`.
        let (mut vm, _vm_mem) = setup_vm(0x1000);
        let mut vcpu = KvmVcpu::new(0, &vm).unwrap();
        vm.setup_irqchip(1).unwrap();
        vcpu.init(vm.fd(), &[]).unwrap();

        assert!(vcpu.dump_cpu_config().is_ok());
    }

    #[test]
    fn test_setup_non_boot_vcpu() {
        let (vm, _) = setup_vm(0x1000);
        let mut vcpu1 = KvmVcpu::new(0, &vm).unwrap();
        assert!(vcpu1.init(vm.fd(), &[]).is_ok());
        let mut vcpu2 = KvmVcpu::new(1, &vm).unwrap();
        assert!(vcpu2.init(vm.fd(), &[]).is_ok());
    }

    #[test]
    fn test_get_valid_regs() {
        // Test `get_regs()` with valid register IDs.
        // - X0: 0x6030 0000 0010 0000
        // - X1: 0x6030 0000 0010 0002
        let (_, vcpu, _) = setup_vcpu(0x10000);
        let reg_list = Vec::<u64>::from([0x6030000000100000, 0x6030000000100002]);
        assert!(get_registers(&vcpu.fd, &reg_list, &mut Aarch64RegisterVec::default()).is_ok());
    }

    #[test]
    fn test_get_invalid_regs() {
        // Test `get_regs()` with invalid register IDs.
        let (_, vcpu, _) = setup_vcpu(0x10000);
        let reg_list = Vec::<u64>::from([0x6030000000100001, 0x6030000000100003]);
        assert!(get_registers(&vcpu.fd, &reg_list, &mut Aarch64RegisterVec::default()).is_err());
    }
}

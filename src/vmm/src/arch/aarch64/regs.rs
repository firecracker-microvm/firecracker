// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::path::PathBuf;

use kvm_bindings::*;
use kvm_ioctls::VcpuFd;
use utils::vm_memory::GuestMemoryMmap;
use versionize::*;
use versionize_derive::Versionize;

use super::get_fdt_addr;

/// Struct describing a saved aarch64 register.
///
/// Used for interacting with `KVM_GET/SET_ONE_REG`.
#[derive(Debug, Clone, PartialEq, Eq, Versionize)]
pub struct Aarch64Register {
    /// The KVM register ID.
    ///
    /// See https://docs.kernel.org/virt/kvm/api.html?highlight=kvm_set_one_reg#kvm-set-one-reg
    pub id: u64,

    /// The value of the register.
    ///
    /// 128 bit wide, as we want to restore the V0-V31 FP SIMD registers,
    /// which are this wide.
    pub value: u128,
}

/// Errors thrown while setting aarch64 registers.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Failed to get a register value.
    #[error("Failed to get register {0}: {1}")]
    GetOneReg(u64, kvm_ioctls::Error),
    /// Failed to set a register value.
    #[error("Failed to set register {0}: {1}")]
    SetOneReg(u64, kvm_ioctls::Error),
    /// Failed to get the register list.
    #[error("Failed to retrieve list of registers: {0}")]
    GetRegList(kvm_ioctls::Error),
    /// Failed to get multiprocessor state.
    #[error("Failed to get multiprocessor state: {0}")]
    GetMp(kvm_ioctls::Error),
    /// Failed to Set multiprocessor state.
    #[error("Failed to set multiprocessor state: {0}")]
    SetMp(kvm_ioctls::Error),
    /// A FamStructWrapper operation has failed.
    #[error("Failed FamStructWrapper operation: {0:?}")]
    Fam(utils::fam::Error),
    /// Failed to get midr_el1 from host.
    #[error("{0}")]
    GetMidrEl1(String),
}

#[allow(non_upper_case_globals)]
// PSR (Processor State Register) bits.
// Taken from arch/arm64/include/uapi/asm/ptrace.h.
const PSR_MODE_EL1h: u64 = 0x0000_0005;
const PSR_F_BIT: u64 = 0x0000_0040;
const PSR_I_BIT: u64 = 0x0000_0080;
const PSR_A_BIT: u64 = 0x0000_0100;
const PSR_D_BIT: u64 = 0x0000_0200;
// Taken from arch/arm64/kvm/inject_fault.c.
const PSTATE_FAULT_BITS_64: u64 = PSR_MODE_EL1h | PSR_A_BIT | PSR_F_BIT | PSR_I_BIT | PSR_D_BIT;

// Following are macros that help with getting the ID of a aarch64 core register.
// The core register are represented by the user_pt_regs structure. Look for it in
// arch/arm64/include/uapi/asm/ptrace.h.

// Gets offset of a member (`field`) within a struct (`container`).
// Same as bindgen offset tests.
macro_rules! offset__of {
    ($container:ty, $field:ident) => {
        // SAFETY: The implementation closely matches that of the memoffset crate,
        // which have been under extensive review.
        unsafe {
            let uninit = std::mem::MaybeUninit::<$container>::uninit();
            let ptr = uninit.as_ptr();
            std::ptr::addr_of!((*ptr).$field) as usize - ptr as usize
        }
    };
}

/// Gets a core id.
macro_rules! arm64_core_reg_id {
    ($size: tt, $offset: tt) => {
        // The core registers of an arm64 machine are represented
        // in kernel by the `kvm_regs` structure. This structure is a
        // mix of 32, 64 and 128 bit fields:
        // struct kvm_regs {
        //     struct user_pt_regs      regs;
        //
        //     __u64                    sp_el1;
        //     __u64                    elr_el1;
        //
        //     __u64                    spsr[KVM_NR_SPSR];
        //
        //     struct user_fpsimd_state fp_regs;
        // };
        // struct user_pt_regs {
        //     __u64 regs[31];
        //     __u64 sp;
        //     __u64 pc;
        //     __u64 pstate;
        // };
        // The id of a core register can be obtained like this:
        // offset = id & ~(KVM_REG_ARCH_MASK | KVM_REG_SIZE_MASK | KVM_REG_ARM_CORE). Thus,
        // id = KVM_REG_ARM64 | KVM_REG_SIZE_U64/KVM_REG_SIZE_U32/KVM_REG_SIZE_U128 |
        // KVM_REG_ARM_CORE | offset
        KVM_REG_ARM64 as u64
            | u64::from(KVM_REG_ARM_CORE)
            | $size
            | (($offset / std::mem::size_of::<u32>()) as u64)
    };
}

// This macro computes the ID of a specific ARM64 system register similar to how
// the kernel C macro does.
// https://elixir.bootlin.com/linux/v4.20.17/source/arch/arm64/include/uapi/asm/kvm.h#L203
macro_rules! arm64_sys_reg {
    ($name: tt, $op0: tt, $op1: tt, $crn: tt, $crm: tt, $op2: tt) => {
        /// System register constant
        pub const $name: u64 = KVM_REG_ARM64 as u64
            | KVM_REG_SIZE_U64 as u64
            | KVM_REG_ARM64_SYSREG as u64
            | ((($op0 as u64) << KVM_REG_ARM64_SYSREG_OP0_SHIFT)
                & KVM_REG_ARM64_SYSREG_OP0_MASK as u64)
            | ((($op1 as u64) << KVM_REG_ARM64_SYSREG_OP1_SHIFT)
                & KVM_REG_ARM64_SYSREG_OP1_MASK as u64)
            | ((($crn as u64) << KVM_REG_ARM64_SYSREG_CRN_SHIFT)
                & KVM_REG_ARM64_SYSREG_CRN_MASK as u64)
            | ((($crm as u64) << KVM_REG_ARM64_SYSREG_CRM_SHIFT)
                & KVM_REG_ARM64_SYSREG_CRM_MASK as u64)
            | ((($op2 as u64) << KVM_REG_ARM64_SYSREG_OP2_SHIFT)
                & KVM_REG_ARM64_SYSREG_OP2_MASK as u64);
    };
}

// Constants imported from the Linux kernel:
// https://elixir.bootlin.com/linux/v4.20.17/source/arch/arm64/include/asm/sysreg.h#L135
arm64_sys_reg!(MPIDR_EL1, 3, 0, 0, 0, 5);
arm64_sys_reg!(MIDR_EL1, 3, 0, 0, 0, 0);

// ID registers that represent cpu capabilities.
// Needed for static cpu templates.
arm64_sys_reg!(ID_AA64PFR0_EL1, 3, 0, 0, 4, 0);
arm64_sys_reg!(ID_AA64ISAR0_EL1, 3, 0, 0, 6, 0);
arm64_sys_reg!(ID_AA64ISAR1_EL1, 3, 0, 0, 6, 1);
arm64_sys_reg!(ID_AA64MMFR2_EL1, 3, 0, 0, 7, 2);

// EL0 Virtual Timer Registers
arm64_sys_reg!(KVM_REG_ARM_TIMER_CNT, 3, 3, 14, 3, 2);

/// Extract the Manufacturer ID from a VCPU state's registers.
/// The ID is found between bits 24-31 of MIDR_EL1 register.
///
/// # Arguments
///
/// * `state` - Array slice of [`Aarch64Register`] structures, representing the registers of a VCPU
///   state.
#[tracing::instrument(level = "trace", ret)]
pub fn get_manufacturer_id_from_state(regs: &[Aarch64Register]) -> Result<u32, Error> {
    let midr_el1 = regs.iter().find(|reg| reg.id == MIDR_EL1);
    match midr_el1 {
        Some(register) => Ok(register.value as u32 >> 24),
        None => Err(Error::GetMidrEl1(
            "Failed to find MIDR_EL1 in vCPU state!".to_string(),
        )),
    }
}

/// Extract the Manufacturer ID from the host.
/// The ID is found between bits 24-31 of MIDR_EL1 register.
#[tracing::instrument(level = "trace", ret)]
pub fn get_manufacturer_id_from_host() -> Result<u32, Error> {
    let midr_el1_path =
        &PathBuf::from("/sys/devices/system/cpu/cpu0/regs/identification/midr_el1".to_string());

    let midr_el1 = std::fs::read_to_string(midr_el1_path).map_err(|err| {
        Error::GetMidrEl1(format!("Failed to get MIDR_EL1 from host path: {err}"))
    })?;
    let midr_el1_trimmed = midr_el1.trim_end().trim_start_matches("0x");
    let manufacturer_id = u32::from_str_radix(midr_el1_trimmed, 16)
        .map_err(|err| Error::GetMidrEl1(format!("Invalid MIDR_EL1 found on host: {err}",)))?;

    Ok(manufacturer_id >> 24)
}

/// Configure relevant boot registers for a given vCPU.
///
/// # Arguments
///
/// * `cpu_id` - Index of current vcpu.
/// * `boot_ip` - Starting instruction pointer.
/// * `mem` - Reserved DRAM for current VM.
#[tracing::instrument(level = "trace", ret)]
pub fn setup_boot_regs(
    vcpufd: &VcpuFd,
    cpu_id: u8,
    boot_ip: u64,
    mem: &GuestMemoryMmap,
) -> Result<(), Error> {
    let kreg_off = offset__of!(kvm_regs, regs);

    // Get the register index of the PSTATE (Processor State) register.
    let pstate = offset__of!(user_pt_regs, pstate) + kreg_off;
    let id = arm64_core_reg_id!(KVM_REG_SIZE_U64, pstate);
    vcpufd
        .set_one_reg(id, PSTATE_FAULT_BITS_64.into())
        .map_err(|err| Error::SetOneReg(id, err))?;

    // Other vCPUs are powered off initially awaiting PSCI wakeup.
    if cpu_id == 0 {
        // Setting the PC (Processor Counter) to the current program address (kernel address).
        let pc = offset__of!(user_pt_regs, pc) + kreg_off;
        let id = arm64_core_reg_id!(KVM_REG_SIZE_U64, pc);
        vcpufd
            .set_one_reg(id, boot_ip.into())
            .map_err(|err| Error::SetOneReg(id, err))?;

        // Last mandatory thing to set -> the address pointing to the FDT (also called DTB).
        // "The device tree blob (dtb) must be placed on an 8-byte boundary and must
        // not exceed 2 megabytes in size." -> https://www.kernel.org/doc/Documentation/arm64/booting.txt.
        // We are choosing to place it the end of DRAM. See `get_fdt_addr`.
        let regs0 = offset__of!(user_pt_regs, regs) + kreg_off;
        let id = arm64_core_reg_id!(KVM_REG_SIZE_U64, regs0);
        vcpufd
            .set_one_reg(id, get_fdt_addr(mem).into())
            .map_err(|err| Error::SetOneReg(id, err))?;
    }
    Ok(())
}

/// Read the MPIDR - Multiprocessor Affinity Register.
#[tracing::instrument(level = "trace", ret)]
pub fn get_mpidr(vcpufd: &VcpuFd) -> Result<u64, Error> {
    match vcpufd.get_one_reg(MPIDR_EL1) {
        Err(err) => Err(Error::GetOneReg(MPIDR_EL1, err)),
        // MPIDR register is 64 bit wide on aarch64, this expect cannot fail
        // on supported architectures
        Ok(val) => Ok(val.try_into().expect("MPIDR register to be 64 bit")),
    }
}

/// Saves the states of the system registers into `state`.
///
/// # Arguments
///
/// * `regs` - Input/Output vector of registers.
#[tracing::instrument(level = "trace", ret)]
pub fn get_all_registers(vcpufd: &VcpuFd, state: &mut Vec<Aarch64Register>) -> Result<(), Error> {
    get_registers(vcpufd, &get_all_registers_ids(vcpufd)?, state)
}

/// Saves states of registers into `state`.
///
/// # Arguments
///
/// * `ids` - Slice of registers ids to save.
/// * `regs` - Input/Output vector of registers.
#[tracing::instrument(level = "trace", ret)]
pub fn get_registers(
    vcpufd: &VcpuFd,
    ids: &[u64],
    regs: &mut Vec<Aarch64Register>,
) -> Result<(), Error> {
    for id in ids.iter() {
        regs.push(Aarch64Register {
            id: *id,
            value: vcpufd
                .get_one_reg(*id)
                .map_err(|e| Error::GetOneReg(*id, e))?,
        });
    }

    Ok(())
}

/// Returns all registers ids, including core and system
#[tracing::instrument(level = "trace", ret)]
pub fn get_all_registers_ids(vcpufd: &VcpuFd) -> Result<Vec<u64>, Error> {
    // Call KVM_GET_REG_LIST to get all registers available to the guest. For ArmV8 there are
    // less than 500 registers.
    let mut reg_list = RegList::new(500).map_err(Error::Fam)?;
    vcpufd
        .get_reg_list(&mut reg_list)
        .map_err(Error::GetRegList)?;
    Ok(reg_list.as_slice().to_vec())
}

/// Set the state of the system registers.
///
/// # Arguments
///
/// * `regs` - Slice of registers to be set.
#[tracing::instrument(level = "trace", ret)]
pub fn set_registers(vcpufd: &VcpuFd, regs: &[Aarch64Register]) -> Result<(), Error> {
    for reg in regs {
        vcpufd
            .set_one_reg(reg.id, reg.value)
            .map_err(|e| Error::SetOneReg(reg.id, e))?;
    }
    Ok(())
}

/// Get the multistate processor.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
#[tracing::instrument(level = "trace", ret)]
pub fn get_mpstate(vcpufd: &VcpuFd) -> Result<kvm_mp_state, Error> {
    vcpufd.get_mp_state().map_err(Error::GetMp)
}

/// Set the state of the system registers.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
/// * `state` - Structure for returning the state of the system registers.
#[tracing::instrument(level = "trace", ret)]
pub fn set_mpstate(vcpufd: &VcpuFd, state: kvm_mp_state) -> Result<(), Error> {
    vcpufd.set_mp_state(state).map_err(Error::SetMp)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]
    use kvm_ioctls::Kvm;

    use super::*;
    use crate::arch::aarch64::{arch_memory_regions, layout};

    #[test]
    fn test_setup_regs() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let regions = arch_memory_regions(layout::FDT_MAX_SIZE + 0x1000);
        let mem = utils::vm_memory::test_utils::create_anon_guest_memory(&regions, false)
            .expect("Cannot initialize memory");

        let res = setup_boot_regs(&vcpu, 0, 0x0, &mem);
        assert_eq!(
            res.unwrap_err(),
            Error::SetOneReg(6931039826524241986, kvm_ioctls::Error::new(8))
        );

        let mut kvi: kvm_bindings::kvm_vcpu_init = kvm_bindings::kvm_vcpu_init::default();
        vm.get_preferred_target(&mut kvi).unwrap();
        vcpu.vcpu_init(&kvi).unwrap();

        assert!(setup_boot_regs(&vcpu, 0, 0x0, &mem).is_ok());
    }
    #[test]
    fn test_read_mpidr() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let mut kvi: kvm_bindings::kvm_vcpu_init = kvm_bindings::kvm_vcpu_init::default();
        vm.get_preferred_target(&mut kvi).unwrap();

        // Must fail when vcpu is not initialized yet.
        let res = get_mpidr(&vcpu);
        assert_eq!(
            res.unwrap_err(),
            Error::GetOneReg(MPIDR_EL1, kvm_ioctls::Error::new(8))
        );

        vcpu.vcpu_init(&kvi).unwrap();
        assert_eq!(get_mpidr(&vcpu).unwrap(), 0x8000_0000);
    }

    #[test]
    fn test_get_set_regs() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let mut kvi: kvm_bindings::kvm_vcpu_init = kvm_bindings::kvm_vcpu_init::default();
        vm.get_preferred_target(&mut kvi).unwrap();

        // Must fail when vcpu is not initialized yet.
        let mut regs = Vec::new();
        let res = get_all_registers(&vcpu, &mut regs);
        assert_eq!(
            res.unwrap_err(),
            Error::GetRegList(kvm_ioctls::Error::new(8))
        );

        vcpu.vcpu_init(&kvi).unwrap();
        get_all_registers(&vcpu, &mut regs).unwrap();

        set_registers(&vcpu, &regs).unwrap();
        let off = offset__of!(user_pt_regs, pstate);
        let id = arm64_core_reg_id!(KVM_REG_SIZE_U64, off);
        let pstate = vcpu
            .get_one_reg(id)
            .expect("Failed to call kvm get one reg");
        assert!(regs.contains(&Aarch64Register { id, value: pstate }));
    }

    #[test]
    fn test_mpstate() {
        use std::os::unix::io::AsRawFd;

        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let mut kvi: kvm_bindings::kvm_vcpu_init = kvm_bindings::kvm_vcpu_init::default();
        vm.get_preferred_target(&mut kvi).unwrap();

        let res = get_mpstate(&vcpu);
        assert!(res.is_ok());
        assert!(set_mpstate(&vcpu, res.unwrap()).is_ok());

        unsafe { libc::close(vcpu.as_raw_fd()) };

        let res = get_mpstate(&vcpu);
        assert_eq!(res.unwrap_err(), Error::GetMp(kvm_ioctls::Error::new(9)));

        let res = set_mpstate(&vcpu, kvm_mp_state::default());
        assert_eq!(res.unwrap_err(), Error::SetMp(kvm_ioctls::Error::new(9)));
    }
}

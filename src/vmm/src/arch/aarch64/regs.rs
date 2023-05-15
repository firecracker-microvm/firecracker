// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::path::PathBuf;
use std::{fs, mem, result, u32};

use kvm_bindings::*;
use kvm_ioctls::VcpuFd;
use utils::vm_memory::GuestMemoryMmap;
use versionize::*;
use versionize_derive::Versionize;

use super::get_fdt_addr;

/// Struct describing a saved aarch64 register.
///
/// Used for interacting with `KVM_GET/SET_ONE_REG`.
#[derive(Debug, Clone, Versionize, PartialEq, Eq)]
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
    /// Failed to get core register (PC, PSTATE or general purpose ones).
    #[error("Failed to get {1} register: {0}")]
    GetCoreRegister(kvm_ioctls::Error, String),
    /// Failed to set core register (PC, PSTATE or general purpose ones).
    #[error("Failed to set {1} register: {0}")]
    SetCoreRegister(kvm_ioctls::Error, String),
    /// Failed to get a system register.
    #[error("Failed to get register: {0}: {1}")]
    GetSysRegister(u64, kvm_ioctls::Error),
    /// Failed to set a system register.
    #[error("Failed to set register {0}: {1}")]
    SetSysRegister(u64, kvm_ioctls::Error),
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
type Result<T> = result::Result<T, Error>;

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

// Number of general purpose registers (i.e X0..X31)
const NR_GP_REGS: usize = 31;
// Number of FP_VREG registers.
const NR_FP_VREGS: usize = 32;

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
            | (($offset / mem::size_of::<u32>()) as u64)
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
pub fn get_manufacturer_id_from_state(state: &[Aarch64Register]) -> Result<u32> {
    let midr_el1 = state.iter().find(|reg| reg.id == MIDR_EL1);
    match midr_el1 {
        Some(register) => Ok(register.value as u32 >> 24),
        None => Err(Error::GetMidrEl1(
            "Failed to find MIDR_EL1 in vCPU state!".to_string(),
        )),
    }
}

/// Extract the Manufacturer ID from the host.
/// The ID is found between bits 24-31 of MIDR_EL1 register.
pub fn get_manufacturer_id_from_host() -> Result<u32> {
    let midr_el1_path =
        &PathBuf::from("/sys/devices/system/cpu/cpu0/regs/identification/midr_el1".to_string());

    let midr_el1 = fs::read_to_string(midr_el1_path).map_err(|err| {
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
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
/// * `cpu_id` - Index of current vcpu.
/// * `boot_ip` - Starting instruction pointer.
/// * `mem` - Reserved DRAM for current VM.
pub fn setup_boot_regs(
    vcpu: &VcpuFd,
    cpu_id: u8,
    boot_ip: u64,
    mem: &GuestMemoryMmap,
) -> Result<()> {
    let kreg_off = offset__of!(kvm_regs, regs);

    // Get the register index of the PSTATE (Processor State) register.
    let pstate = offset__of!(user_pt_regs, pstate) + kreg_off;
    vcpu.set_one_reg(
        arm64_core_reg_id!(KVM_REG_SIZE_U64, pstate),
        PSTATE_FAULT_BITS_64.into(),
    )
    .map_err(|err| Error::SetCoreRegister(err, "processor state".to_string()))?;

    // Other vCPUs are powered off initially awaiting PSCI wakeup.
    if cpu_id == 0 {
        // Setting the PC (Processor Counter) to the current program address (kernel address).
        let pc = offset__of!(user_pt_regs, pc) + kreg_off;
        vcpu.set_one_reg(arm64_core_reg_id!(KVM_REG_SIZE_U64, pc), boot_ip.into())
            .map_err(|err| Error::SetCoreRegister(err, "program counter".to_string()))?;

        // Last mandatory thing to set -> the address pointing to the FDT (also called DTB).
        // "The device tree blob (dtb) must be placed on an 8-byte boundary and must
        // not exceed 2 megabytes in size." -> https://www.kernel.org/doc/Documentation/arm64/booting.txt.
        // We are choosing to place it the end of DRAM. See `get_fdt_addr`.
        let regs0 = offset__of!(user_pt_regs, regs) + kreg_off;
        vcpu.set_one_reg(
            arm64_core_reg_id!(KVM_REG_SIZE_U64, regs0),
            get_fdt_addr(mem).into(),
        )
        .map_err(|err| Error::SetCoreRegister(err, "X0".to_string()))?;
    }
    Ok(())
}

/// Specifies whether a particular register is a system register or not.
/// The kernel splits the registers on aarch64 in core registers and system registers.
/// So, below we get the system registers by checking that they are not core registers.
///
/// # Arguments
///
/// * `regid` - The index of the register we are checking.
pub fn is_system_register(regid: u64) -> bool {
    if (regid & u64::from(KVM_REG_ARM_COPROC_MASK)) == u64::from(KVM_REG_ARM_CORE) {
        return false;
    }

    let size = regid & KVM_REG_SIZE_MASK;
    if size != KVM_REG_SIZE_U32 && size != KVM_REG_SIZE_U64 {
        panic!("Unexpected register size for system register {}", size);
    }
    true
}

/// Read the MPIDR - Multiprocessor Affinity Register.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
pub fn read_mpidr(vcpu: &VcpuFd) -> Result<u64> {
    match vcpu.get_one_reg(MPIDR_EL1) {
        Err(err) => Err(Error::GetSysRegister(MPIDR_EL1, err)),
        // MPIDR register is 64 bit wide on aarch64, this expect cannot fail
        // on supported architectures
        Ok(val) => Ok(val.try_into().expect("MPIDR register to be 64 bit")),
    }
}

/// Saves the states of the core registers into `state`.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
/// * `state` - Input/Output vector of registers states.
pub fn save_core_registers(vcpu: &VcpuFd, state: &mut Vec<Aarch64Register>) -> Result<()> {
    let mut off = offset__of!(user_pt_regs, regs);
    // There are 31 user_pt_regs:
    // https://elixir.free-electrons.com/linux/v4.14.174/source/arch/arm64/include/uapi/asm/ptrace.h#L72
    // These actually are the general-purpose registers of the Armv8-a
    // architecture (i.e x0-x30 if used as a 64bit register or w0-w30 when used as a 32bit
    // register).
    for i in 0..NR_GP_REGS {
        let id = arm64_core_reg_id!(KVM_REG_SIZE_U64, off);
        state.push(Aarch64Register {
            id,
            value: vcpu
                .get_one_reg(id)
                .map_err(|err| Error::GetCoreRegister(err, format!("X{}", i)))?,
        });
        off += std::mem::size_of::<u64>();
    }

    // We are now entering the "Other register" section of the ARMv8-a architecture.
    // First one, stack pointer.
    let off = offset__of!(user_pt_regs, sp);
    let id = arm64_core_reg_id!(KVM_REG_SIZE_U64, off);
    state.push(Aarch64Register {
        id,
        value: vcpu
            .get_one_reg(id)
            .map_err(|err| Error::GetCoreRegister(err, "stack pointer".to_string()))?,
    });

    // Second one, the program counter.
    let off = offset__of!(user_pt_regs, pc);
    let id = arm64_core_reg_id!(KVM_REG_SIZE_U64, off);
    state.push(Aarch64Register {
        id,
        value: vcpu
            .get_one_reg(id)
            .map_err(|err| Error::GetCoreRegister(err, "program counter".to_string()))?,
    });

    // Next is the processor state.
    let off = offset__of!(user_pt_regs, pstate);
    let id = arm64_core_reg_id!(KVM_REG_SIZE_U64, off);
    state.push(Aarch64Register {
        id,
        value: vcpu
            .get_one_reg(id)
            .map_err(|err| Error::GetCoreRegister(err, "processor state".to_string()))?,
    });

    // The stack pointer associated with EL1.
    let off = offset__of!(kvm_regs, sp_el1);
    let id = arm64_core_reg_id!(KVM_REG_SIZE_U64, off);
    state.push(Aarch64Register {
        id,
        value: vcpu
            .get_one_reg(id)
            .map_err(|err| Error::GetCoreRegister(err, "SP_EL1".to_string()))?,
    });

    // Exception Link Register for EL1, when taking an exception to EL1, this register
    // holds the address to which to return afterwards.
    let off = offset__of!(kvm_regs, elr_el1);
    let id = arm64_core_reg_id!(KVM_REG_SIZE_U64, off);
    state.push(Aarch64Register {
        id,
        value: vcpu
            .get_one_reg(id)
            .map_err(|err| Error::GetCoreRegister(err, "ELR_EL1".to_string()))?,
    });

    // Saved Program Status Registers, there are 5 of them used in the kernel.
    let mut off = offset__of!(kvm_regs, spsr);
    for i in 0..KVM_NR_SPSR {
        let id = arm64_core_reg_id!(KVM_REG_SIZE_U64, off);
        state.push(Aarch64Register {
            id,
            value: vcpu
                .get_one_reg(id)
                .map_err(|err| Error::GetCoreRegister(err, format!("SPSR{}", i)))?,
        });
        off += std::mem::size_of::<u64>();
    }

    // Now moving on to floating point registers which are stored in the user_fpsimd_state in the
    // kernel: https://elixir.free-electrons.com/linux/v4.9.62/source/arch/arm64/include/uapi/asm/kvm.h#L53
    let mut off = offset__of!(kvm_regs, fp_regs) + offset__of!(user_fpsimd_state, vregs);
    for i in 0..NR_FP_VREGS {
        let id = arm64_core_reg_id!(KVM_REG_SIZE_U128, off);
        state.push(Aarch64Register {
            id,
            value: vcpu
                .get_one_reg(id)
                .map_err(|err| Error::GetCoreRegister(err, format!("FP_VREG{}", i)))?,
        });
        off += mem::size_of::<u128>();
    }

    // Floating-point Status Register.
    let off = offset__of!(kvm_regs, fp_regs) + offset__of!(user_fpsimd_state, fpsr);
    let id = arm64_core_reg_id!(KVM_REG_SIZE_U32, off);
    state.push(Aarch64Register {
        id,
        value: vcpu
            .get_one_reg(id)
            .map_err(|err| Error::GetCoreRegister(err, "FPSR".to_string()))?,
    });

    // Floating-point Control Register.
    let off = offset__of!(kvm_regs, fp_regs) + offset__of!(user_fpsimd_state, fpcr);
    let id = arm64_core_reg_id!(KVM_REG_SIZE_U32, off);
    state.push(Aarch64Register {
        id,
        value: vcpu
            .get_one_reg(id)
            .map_err(|err| Error::GetCoreRegister(err, "FPCR".to_string()))?,
    });

    Ok(())
}

/// Saves the states of the system registers into `state`.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
/// * `state` - Input/Output vector of registers states.
pub fn save_system_registers(vcpu: &VcpuFd, state: &mut Vec<Aarch64Register>) -> Result<()> {
    // Call KVM_GET_REG_LIST to get all registers available to the guest. For ArmV8 there are
    // less than 500 registers.
    let mut reg_list = RegList::new(500).map_err(Error::Fam)?;
    vcpu.get_reg_list(&mut reg_list)
        .map_err(Error::GetRegList)?;

    // At this point reg_list should contain: core registers and system registers.
    // The register list contains the number of registers and their ids. We will be needing to
    // call KVM_GET_ONE_REG on each id in order to save all of them. We carve out from the list
    // the core registers which are represented in the kernel by kvm_regs structure and for which
    // we can calculate the id based on the offset in the structure.
    reg_list.retain(|regid| is_system_register(*regid));

    // Now, for the rest of the registers left in the previously fetched register list, we are
    // simply calling KVM_GET_ONE_REG.
    save_registers(vcpu, reg_list.as_slice(), state)?;

    Ok(())
}

/// Saves states of registers into `state`.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
/// * `ids` - Slice of registers ids to save.
/// * `state` - Input/Output vector of registers states.
pub fn save_registers(vcpu: &VcpuFd, ids: &[u64], state: &mut Vec<Aarch64Register>) -> Result<()> {
    for id in ids.iter() {
        state.push(Aarch64Register {
            id: *id,
            value: vcpu
                .get_one_reg(*id)
                .map_err(|e| Error::GetSysRegister(*id, e))?,
        });
    }

    Ok(())
}

/// Set the state of the system registers.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
/// * `state` - Structure containing the state of the system registers.
pub fn restore_registers(vcpu: &VcpuFd, state: &[Aarch64Register]) -> Result<()> {
    for reg in state {
        vcpu.set_one_reg(reg.id, reg.value)
            .map_err(|e| Error::SetSysRegister(reg.id, e))?;
    }
    Ok(())
}

/// Get the multistate processor.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
pub fn get_mpstate(vcpu: &VcpuFd) -> Result<kvm_mp_state> {
    vcpu.get_mp_state().map_err(Error::GetMp)
}

/// Set the state of the system registers.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
/// * `state` - Structure for returning the state of the system registers.
pub fn set_mpstate(vcpu: &VcpuFd, state: kvm_mp_state) -> Result<()> {
    vcpu.set_mp_state(state).map_err(Error::SetMp)
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
            Error::SetCoreRegister(kvm_ioctls::Error::new(8), "processor state".to_string())
        );

        let mut kvi: kvm_bindings::kvm_vcpu_init = kvm_bindings::kvm_vcpu_init::default();
        vm.get_preferred_target(&mut kvi).unwrap();
        vcpu.vcpu_init(&kvi).unwrap();

        setup_boot_regs(&vcpu, 0, 0x0, &mem).unwrap();
    }
    #[test]
    fn test_read_mpidr() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let mut kvi: kvm_bindings::kvm_vcpu_init = kvm_bindings::kvm_vcpu_init::default();
        vm.get_preferred_target(&mut kvi).unwrap();

        // Must fail when vcpu is not initialized yet.
        let res = read_mpidr(&vcpu);
        assert_eq!(
            res.unwrap_err(),
            Error::GetSysRegister(MPIDR_EL1, kvm_ioctls::Error::new(8))
        );

        vcpu.vcpu_init(&kvi).unwrap();
        assert_eq!(read_mpidr(&vcpu).unwrap(), 0x8000_0000);
    }

    #[test]
    fn test_is_system_register() {
        let offset = offset__of!(user_pt_regs, pc);
        let regid = arm64_core_reg_id!(KVM_REG_SIZE_U64, offset);
        assert!(!is_system_register(regid));
        let regid =
            KVM_REG_ARM64 | KVM_REG_SIZE_U64 | u64::from(kvm_bindings::KVM_REG_ARM64_SYSREG);
        assert!(is_system_register(regid));
    }

    #[test]
    #[should_panic]
    fn test_is_not_system_register() {
        assert!(is_system_register(0));
    }

    #[test]
    fn test_save_restore_regs() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let mut kvi: kvm_bindings::kvm_vcpu_init = kvm_bindings::kvm_vcpu_init::default();
        vm.get_preferred_target(&mut kvi).unwrap();

        // Must fail when vcpu is not initialized yet.
        let mut state = Vec::new();
        let res = save_core_registers(&vcpu, &mut state);
        assert_eq!(
            res.unwrap_err(),
            Error::GetCoreRegister(kvm_ioctls::Error::new(8), "X0".to_string())
        );

        let res = save_system_registers(&vcpu, &mut state);
        assert_eq!(
            res.unwrap_err(),
            Error::GetRegList(kvm_ioctls::Error::new(8))
        );

        vcpu.vcpu_init(&kvi).unwrap();
        save_core_registers(&vcpu, &mut state).unwrap();
        save_system_registers(&vcpu, &mut state).unwrap();

        restore_registers(&vcpu, &state).unwrap();
        let off = offset__of!(user_pt_regs, pstate);
        let id = arm64_core_reg_id!(KVM_REG_SIZE_U64, off);
        let pstate = vcpu
            .get_one_reg(id)
            .expect("Failed to call kvm get one reg");
        assert!(state.contains(&Aarch64Register { id, value: pstate }));
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

// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::{fmt, fs, mem, result, u32};

use super::get_fdt_addr;
use kvm_bindings::*;
use kvm_ioctls::VcpuFd;
use std::path::PathBuf;
use vm_memory::GuestMemoryMmap;

/// Errors thrown while setting aarch64 registers.
#[derive(Debug)]
pub enum Error {
    /// Failed to get core register (PC, PSTATE or general purpose ones).
    GetCoreRegister(kvm_ioctls::Error, String),
    /// Failed to get multiprocessor state.
    GetMP(kvm_ioctls::Error),
    /// Failed to get the register list.
    GetRegList(kvm_ioctls::Error),
    /// Failed to get a system register.
    GetSysRegister(kvm_ioctls::Error),
    /// A FamStructWrapper operation has failed.
    FamError(utils::fam::Error),
    /// Failed to set core register (PC, PSTATE or general purpose ones).
    SetCoreRegister(kvm_ioctls::Error, String),
    /// Failed to Set multiprocessor state.
    SetMP(kvm_ioctls::Error),
    /// Failed to get a system register.
    SetRegister(kvm_ioctls::Error),
    /// Failed to get midr_el1 from host.
    GetMidrEl1(String),
}
type Result<T> = result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match *self {
            GetCoreRegister(ref e, ref desc) => write!(f, "Failed to get {} register: {}", desc, e),
            GetMP(ref e) => write!(f, "Failed to get multiprocessor state: {}", e),
            GetRegList(ref e) => write!(f, "Failed to retrieve list of registers: {}", e),
            GetSysRegister(ref e) => write!(f, "Failed to get system register: {}", e),
            SetCoreRegister(ref e, ref desc) => write!(f, "Failed to set {} register: {}", desc, e),
            SetMP(ref e) => write!(f, "Failed to set multiprocessor state: {}", e),
            SetRegister(ref e) => write!(f, "Failed to set register: {}", e),
            GetMidrEl1(ref e) => write!(f, "{}", e),
            FamError(ref e) => write!(f, "Failed FamStructWrapper operation: {:?}", e),
        }
    }
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

// Number of general purpose registers (i.e X0..X31)
const NR_GP_REGS: usize = 31;
// Number of FP_VREG registers.
const NR_FP_VREGS: usize = 32;

// Following are macros that help with getting the ID of a aarch64 core register.
// The core register are represented by the user_pt_regs structure. Look for it in
// arch/arm64/include/uapi/asm/ptrace.h.

// This macro gets the offset of a structure (i.e `str`) member (i.e `field`) without having
// an instance of that structure.
// It uses a null pointer to retrieve the offset to the field.
// Inspired by C solution: `#define offsetof(str, f) ((size_t)(&((str *)0)->f))`.
// Doing `offset__of!(user_pt_regs, pstate)` in our rust code will trigger the following:
// unsafe { &(*(0 as *const user_pt_regs)).pstate as *const _ as usize }
// The dereference expression produces an lvalue, but that lvalue is not actually read from,
// we're just doing pointer math on it, so in theory, it should be safe.
macro_rules! offset__of {
    ($str:ty, $field:ident) => {
        unsafe { &(*(std::ptr::null::<$str>())).$field as *const _ as usize }
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
        // id = KVM_REG_ARM64 | KVM_REG_SIZE_U64/KVM_REG_SIZE_U32/KVM_REG_SIZE_U128 | KVM_REG_ARM_CORE | offset
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

// Constant imported from the Linux kernel:
// https://elixir.bootlin.com/linux/v4.20.17/source/arch/arm64/include/asm/sysreg.h#L135
arm64_sys_reg!(MPIDR_EL1, 3, 0, 0, 0, 5);
arm64_sys_reg!(MIDR_EL1, 3, 0, 0, 0, 0);

/// Extract the Manufacturer ID from a VCPU state's registers.
/// The ID is found between bits 24-31 of MIDR_EL1 register.
///
/// # Arguments
///
/// * `state` - Array slice of kvm_one_reg structures, representing
///             the registers of a VCPU state.
pub fn get_manufacturer_id_from_state(state: &[kvm_one_reg]) -> Result<u32> {
    let midr_el1 = state.iter().find(|reg| reg.id == MIDR_EL1);
    match midr_el1 {
        Some(value) => Ok(value.addr as u32 >> 24),
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

    let midr_el1 = fs::read_to_string(midr_el1_path).map_err(|e| {
        Error::GetMidrEl1(format!(
            "Failed to get MIDR_EL1 from host path: {}",
            e.to_string()
        ))
    })?;
    let midr_el1_trimmed = midr_el1.trim_end().trim_start_matches("0x");
    let manufacturer_id = u32::from_str_radix(midr_el1_trimmed, 16).map_err(|e| {
        Error::GetMidrEl1(format!("Invalid MIDR_EL1 found on host: {}", e.to_string()))
    })?;

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
        PSTATE_FAULT_BITS_64,
    )
    .map_err(|e| Error::SetCoreRegister(e, "processor state".to_string()))?;

    // Other vCPUs are powered off initially awaiting PSCI wakeup.
    if cpu_id == 0 {
        // Setting the PC (Processor Counter) to the current program address (kernel address).
        let pc = offset__of!(user_pt_regs, pc) + kreg_off;
        vcpu.set_one_reg(arm64_core_reg_id!(KVM_REG_SIZE_U64, pc), boot_ip as u64)
            .map_err(|e| Error::SetCoreRegister(e, "program counter".to_string()))?;

        // Last mandatory thing to set -> the address pointing to the FDT (also called DTB).
        // "The device tree blob (dtb) must be placed on an 8-byte boundary and must
        // not exceed 2 megabytes in size." -> https://www.kernel.org/doc/Documentation/arm64/booting.txt.
        // We are choosing to place it the end of DRAM. See `get_fdt_addr`.
        let regs0 = offset__of!(user_pt_regs, regs) + kreg_off;
        vcpu.set_one_reg(
            arm64_core_reg_id!(KVM_REG_SIZE_U64, regs0),
            get_fdt_addr(mem) as u64,
        )
        .map_err(|e| Error::SetCoreRegister(e, "X0".to_string()))?;
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
    if (regid & KVM_REG_ARM_COPROC_MASK as u64) == KVM_REG_ARM_CORE as u64 {
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
    vcpu.get_one_reg(MPIDR_EL1).map_err(Error::GetSysRegister)
}

/// Get the state of the core registers.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
/// * `state` - Structure for returning the state of the core registers.
pub fn save_core_registers(vcpu: &VcpuFd, state: &mut Vec<kvm_one_reg>) -> Result<()> {
    let mut off = offset__of!(user_pt_regs, regs);
    // There are 31 user_pt_regs:
    // https://elixir.free-electrons.com/linux/v4.14.174/source/arch/arm64/include/uapi/asm/ptrace.h#L72
    // These actually are the general-purpose registers of the Armv8-a
    // architecture (i.e x0-x30 if used as a 64bit register or w0-w30 when used as a 32bit register).
    for i in 0..NR_GP_REGS {
        let id = arm64_core_reg_id!(KVM_REG_SIZE_U64, off);
        state.push(kvm_one_reg {
            id,
            addr: vcpu
                .get_one_reg(id)
                .map_err(|e| Error::GetCoreRegister(e, format!("X{}", i)))?,
        });
        off += std::mem::size_of::<u64>();
    }

    // We are now entering the "Other register" section of the ARMv8-a architecture.
    // First one, stack pointer.
    let off = offset__of!(user_pt_regs, sp);
    let id = arm64_core_reg_id!(KVM_REG_SIZE_U64, off);
    state.push(kvm_one_reg {
        id,
        addr: vcpu
            .get_one_reg(id)
            .map_err(|e| Error::GetCoreRegister(e, "stack pointer".to_string()))?,
    });

    // Second one, the program counter.
    let off = offset__of!(user_pt_regs, pc);
    let id = arm64_core_reg_id!(KVM_REG_SIZE_U64, off);
    state.push(kvm_one_reg {
        id,
        addr: vcpu
            .get_one_reg(id)
            .map_err(|e| Error::GetCoreRegister(e, "program counter".to_string()))?,
    });

    // Next is the processor state.
    let off = offset__of!(user_pt_regs, pstate);
    let id = arm64_core_reg_id!(KVM_REG_SIZE_U64, off);
    state.push(kvm_one_reg {
        id,
        addr: vcpu
            .get_one_reg(id)
            .map_err(|e| Error::GetCoreRegister(e, "processor state".to_string()))?,
    });

    // The stack pointer associated with EL1.
    let off = offset__of!(kvm_regs, sp_el1);
    let id = arm64_core_reg_id!(KVM_REG_SIZE_U64, off);
    state.push(kvm_one_reg {
        id,
        addr: vcpu
            .get_one_reg(id)
            .map_err(|e| Error::GetCoreRegister(e, "SP_EL1".to_string()))?,
    });

    // Exception Link Register for EL1, when taking an exception to EL1, this register
    // holds the address to which to return afterwards.
    let off = offset__of!(kvm_regs, elr_el1);
    let id = arm64_core_reg_id!(KVM_REG_SIZE_U64, off);
    state.push(kvm_one_reg {
        id,
        addr: vcpu
            .get_one_reg(id)
            .map_err(|e| Error::GetCoreRegister(e, "ELR_EL1".to_string()))?,
    });

    // Saved Program Status Registers, there are 5 of them used in the kernel.
    let mut off = offset__of!(kvm_regs, spsr);
    for i in 0..KVM_NR_SPSR {
        let id = arm64_core_reg_id!(KVM_REG_SIZE_U64, off);
        state.push(kvm_one_reg {
            id,
            addr: vcpu
                .get_one_reg(id)
                .map_err(|e| Error::GetCoreRegister(e, format!("SPSR{}", i)))?,
        });
        off += std::mem::size_of::<u64>();
    }

    // Now moving on to floating point registers which are stored in the user_fpsimd_state in the kernel:
    // https://elixir.free-electrons.com/linux/v4.9.62/source/arch/arm64/include/uapi/asm/kvm.h#L53
    let mut off = offset__of!(kvm_regs, fp_regs) + offset__of!(user_fpsimd_state, vregs);
    for i in 0..NR_FP_VREGS {
        let id = arm64_core_reg_id!(KVM_REG_SIZE_U128, off);
        state.push(kvm_one_reg {
            id,
            addr: vcpu
                .get_one_reg(id)
                .map_err(|e| Error::GetCoreRegister(e, format!("FP_VREG{}", i)))?,
        });
        off += mem::size_of::<u128>();
    }

    // Floating-point Status Register.
    let off = offset__of!(kvm_regs, fp_regs) + offset__of!(user_fpsimd_state, fpsr);
    let id = arm64_core_reg_id!(KVM_REG_SIZE_U32, off);
    state.push(kvm_one_reg {
        id,
        addr: vcpu
            .get_one_reg(id)
            .map_err(|e| Error::GetCoreRegister(e, "FPSR".to_string()))?,
    });

    // Floating-point Control Register.
    let off = offset__of!(kvm_regs, fp_regs) + offset__of!(user_fpsimd_state, fpcr);
    let id = arm64_core_reg_id!(KVM_REG_SIZE_U32, off);
    state.push(kvm_one_reg {
        id,
        addr: vcpu
            .get_one_reg(id)
            .map_err(|e| Error::GetCoreRegister(e, "FPCR".to_string()))?,
    });

    Ok(())
}

/// Get the state of the system registers.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
/// * `state` - Structure for returning the state of the system registers.
pub fn save_system_registers(vcpu: &VcpuFd, state: &mut Vec<kvm_one_reg>) -> Result<()> {
    // Call KVM_GET_REG_LIST to get all registers available to the guest. For ArmV8 there are
    // less than 500 registers.
    let mut reg_list = RegList::new(500).map_err(Error::FamError)?;
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
    let indices = reg_list.as_slice();
    for index in indices.iter() {
        state.push(kvm_bindings::kvm_one_reg {
            id: *index,
            addr: vcpu.get_one_reg(*index).map_err(Error::GetSysRegister)?,
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
pub fn restore_registers(vcpu: &VcpuFd, state: &[kvm_one_reg]) -> Result<()> {
    for reg in state {
        vcpu.set_one_reg(reg.id, reg.addr)
            .map_err(Error::SetRegister)?;
    }
    Ok(())
}

/// Get the multistate processor.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
pub fn get_mpstate(vcpu: &VcpuFd) -> Result<kvm_mp_state> {
    vcpu.get_mp_state().map_err(Error::GetMP)
}

/// Set the state of the system registers.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
/// * `state` - Structure for returning the state of the system registers.
pub fn set_mpstate(vcpu: &VcpuFd, state: kvm_mp_state) -> Result<()> {
    vcpu.set_mp_state(state).map_err(Error::SetMP)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::{arch_memory_regions, layout};
    use kvm_ioctls::Kvm;

    #[test]
    fn test_setup_regs() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let regions = arch_memory_regions(layout::FDT_MAX_SIZE + 0x1000);
        let mem = GuestMemoryMmap::from_ranges(&regions).expect("Cannot initialize memory");

        let res = setup_boot_regs(&vcpu, 0, 0x0, &mem);
        assert!(res.is_err());
        assert_eq!(
            format!("{}", res.unwrap_err()),
            "Failed to set processor state register: Exec format error (os error 8)"
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
        let res = read_mpidr(&vcpu);
        assert!(res.is_err());
        assert_eq!(
            format!("{}", res.unwrap_err()),
            "Failed to get system register: Exec format error (os error 8)"
        );

        vcpu.vcpu_init(&kvi).unwrap();
        assert_eq!(read_mpidr(&vcpu).unwrap(), 0x8000_0000);
    }

    #[test]
    fn test_is_system_register() {
        let offset = offset__of!(user_pt_regs, pc);
        let regid = arm64_core_reg_id!(KVM_REG_SIZE_U64, offset);
        assert!(!is_system_register(regid));
        let regid = KVM_REG_ARM64 as u64
            | KVM_REG_SIZE_U64 as u64
            | kvm_bindings::KVM_REG_ARM64_SYSREG as u64;
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
        assert!(res.is_err());
        assert_eq!(
            format!("{}", res.unwrap_err()),
            "Failed to get X0 register: Exec format error (os error 8)"
        );

        let res = save_system_registers(&vcpu, &mut state);
        assert!(res.is_err());
        assert_eq!(
            format!("{}", res.unwrap_err()),
            "Failed to retrieve list of registers: Exec format error (os error 8)"
        );

        vcpu.vcpu_init(&kvi).unwrap();
        assert!(save_core_registers(&vcpu, &mut state).is_ok());
        assert!(save_system_registers(&vcpu, &mut state).is_ok());

        assert!(restore_registers(&vcpu, &state).is_ok());
        let off = offset__of!(user_pt_regs, pstate);
        let id = arm64_core_reg_id!(KVM_REG_SIZE_U64, off);
        let pstate = vcpu
            .get_one_reg(id)
            .expect("Failed to call kvm get one reg");
        assert!(state.contains(&kvm_bindings::kvm_one_reg { id, addr: pstate }));
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
        assert!(res.is_err());
        &&assert_eq!(
            format!("{}", res.unwrap_err()),
            "Failed to get multiprocessor state: Bad file descriptor (os error 9)"
        );

        let res = set_mpstate(&vcpu, kvm_mp_state::default());
        assert!(res.is_err());
        &&assert_eq!(
            format!("{}", res.unwrap_err()),
            "Failed to set multiprocessor state: Bad file descriptor (os error 9)"
        );
    }
}

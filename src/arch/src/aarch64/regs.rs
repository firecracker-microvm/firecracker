// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::{fmt, mem, result};

use super::get_fdt_addr;
use kvm_bindings::{
    kvm_regs, user_pt_regs, KVM_REG_ARM64, KVM_REG_ARM64_SYSREG, KVM_REG_ARM64_SYSREG_CRM_MASK,
    KVM_REG_ARM64_SYSREG_CRM_SHIFT, KVM_REG_ARM64_SYSREG_CRN_MASK, KVM_REG_ARM64_SYSREG_CRN_SHIFT,
    KVM_REG_ARM64_SYSREG_OP0_MASK, KVM_REG_ARM64_SYSREG_OP0_SHIFT, KVM_REG_ARM64_SYSREG_OP1_MASK,
    KVM_REG_ARM64_SYSREG_OP1_SHIFT, KVM_REG_ARM64_SYSREG_OP2_MASK, KVM_REG_ARM64_SYSREG_OP2_SHIFT,
    KVM_REG_ARM_CORE, KVM_REG_SIZE_U64,
};
use kvm_ioctls::VcpuFd;
use vm_memory::GuestMemoryMmap;

/// Errors thrown while setting aarch64 registers.
#[derive(Debug)]
pub enum Error {
    /// Failed to set core register (PC, PSTATE or general purpose ones).
    SetCoreRegister(kvm_ioctls::Error),
    /// Failed to get a system register.
    GetSysRegister(kvm_ioctls::Error),
}
type Result<T> = result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            self::Error::SetCoreRegister(ref e) => write!(f, "Failed to set core register: {}", e),
            self::Error::GetSysRegister(ref e) => write!(f, "Failed to get system register: {}", e),
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
// we're just doing pointer math on it, so in theory, it should safe.
macro_rules! offset__of {
    ($str:ty, $field:ident) => {
        unsafe { &(*(std::ptr::null::<$str>())).$field as *const _ as usize }
    };
}

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
        const $name: u64 = KVM_REG_ARM64 as u64
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
    .map_err(Error::SetCoreRegister)?;

    // Other vCPUs are powered off initially awaiting PSCI wakeup.
    if cpu_id == 0 {
        // Setting the PC (Processor Counter) to the current program address (kernel address).
        let pc = offset__of!(user_pt_regs, pc) + kreg_off;
        vcpu.set_one_reg(arm64_core_reg_id!(KVM_REG_SIZE_U64, pc), boot_ip as u64)
            .map_err(Error::SetCoreRegister)?;

        // Last mandatory thing to set -> the address pointing to the FDT (also called DTB).
        // "The device tree blob (dtb) must be placed on an 8-byte boundary and must
        // not exceed 2 megabytes in size." -> https://www.kernel.org/doc/Documentation/arm64/booting.txt.
        // We are choosing to place it the end of DRAM. See `get_fdt_addr`.
        let regs0 = offset__of!(user_pt_regs, regs) + kreg_off;
        vcpu.set_one_reg(
            arm64_core_reg_id!(KVM_REG_SIZE_U64, regs0),
            get_fdt_addr(mem) as u64,
        )
        .map_err(Error::SetCoreRegister)?;
    }
    Ok(())
}

/// Read the MPIDR - Multiprocessor Affinity Register.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
pub fn read_mpidr(vcpu: &VcpuFd) -> Result<u64> {
    vcpu.get_one_reg(MPIDR_EL1).map_err(Error::GetSysRegister)
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
            "Failed to set core register: Exec format error (os error 8)"
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
}

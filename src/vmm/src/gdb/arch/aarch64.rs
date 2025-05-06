// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::mem::offset_of;

use gdbstub_arch::aarch64::reg::AArch64CoreRegs as CoreRegs;
use kvm_bindings::{
    KVM_GUESTDBG_ENABLE, KVM_GUESTDBG_SINGLESTEP, KVM_GUESTDBG_USE_HW, KVM_GUESTDBG_USE_SW_BP,
    KVM_REG_ARM_CORE, KVM_REG_ARM64, KVM_REG_SIZE_U64, kvm_guest_debug, kvm_regs, user_pt_regs,
};
use kvm_ioctls::VcpuFd;
use vm_memory::{Bytes, GuestAddress};

use crate::Vmm;
use crate::arch::aarch64::regs::{
    Aarch64RegisterVec, ID_AA64MMFR0_EL1, TCR_EL1, TTBR1_EL1, arm64_core_reg_id,
};
use crate::arch::aarch64::vcpu::get_registers;
use crate::gdb::target::GdbTargetError;

/// Configures the number of bytes required for a software breakpoint.
///
/// The breakpoint instruction operation also includes the immediate argument which we 0 hence the
/// size.
pub const SW_BP_SIZE: usize = 4;

/// The bytes stored for a software breakpoint.
///
/// This is the BRK instruction with a 0 immediate argument.
/// https://developer.arm.com/documentation/ddi0602/2024-09/Base-Instructions/BRK--Breakpoint-instruction-
pub const SW_BP: [u8; SW_BP_SIZE] = [0, 0, 32, 212];

/// Register id for the program counter
const PC_REG_ID: u64 = arm64_core_reg_id!(KVM_REG_SIZE_U64, offset_of!(user_pt_regs, pc));

/// Retrieve a single register from a Vcpu
fn get_sys_reg(reg: u64, vcpu_fd: &VcpuFd) -> Result<u64, GdbTargetError> {
    let mut register_vec = Aarch64RegisterVec::default();
    get_registers(vcpu_fd, &[reg], &mut register_vec)?;
    let register = register_vec
        .iter()
        .next()
        .ok_or(GdbTargetError::ReadRegisterVecError)?;

    Ok(register.value())
}

/// Gets the PC value for a Vcpu
pub fn get_instruction_pointer(vcpu_fd: &VcpuFd) -> Result<u64, GdbTargetError> {
    get_sys_reg(PC_REG_ID, vcpu_fd)
}

/// Helper to extract a specific number of bits at an offset from a u64
macro_rules! extract_bits_64 {
    ($value: tt, $offset: tt, $length: tt) => {
        ($value >> $offset) & (!0u64 >> (64 - $length))
    };
}

/// Mask to clear the last 3 bits from the page table entry
const PTE_ADDRESS_MASK: u64 = !0b111u64;

/// Read a u64 value from a guest memory address
fn read_address(vmm: &Vmm, address: u64) -> Result<u64, GdbTargetError> {
    let mut buf = [0; 8];
    vmm.vm
        .guest_memory()
        .read(&mut buf, GuestAddress(address))?;

    Ok(u64::from_le_bytes(buf))
}

/// The grainsize used with 4KB paging
const GRAIN_SIZE: usize = 9;

/// Translates a virtual address according to the Vcpu's current address translation mode.
/// Returns the GPA (guest physical address)
///
/// To simplify the implementation we've made some assumptions about the paging setup.
/// Here we just assert firstly paging is setup and these assumptions are correct.
pub fn translate_gva(vcpu_fd: &VcpuFd, gva: u64, vmm: &Vmm) -> Result<u64, GdbTargetError> {
    // Check this virtual address is in kernel space
    if extract_bits_64!(gva, 55, 1) == 0 {
        return Err(GdbTargetError::GvaTranslateError);
    }

    // Translation control register
    let tcr_el1: u64 = get_sys_reg(TCR_EL1, vcpu_fd)?;

    // If this is 0 then translation is not yet ready
    if extract_bits_64!(tcr_el1, 16, 6) == 0 {
        return Ok(gva);
    }

    // Check 4KB pages are being used
    if extract_bits_64!(tcr_el1, 30, 2) != 2 {
        return Err(GdbTargetError::GvaTranslateError);
    }

    // ID_AA64MMFR0_EL1 provides information about the implemented memory model and memory
    // management. Check this is a physical address size we support
    let pa_size = match get_sys_reg(ID_AA64MMFR0_EL1, vcpu_fd)? & 0b1111 {
        0 => 32,
        1 => 36,
        2 => 40,
        3 => 42,
        4 => 44,
        5 => 48,
        _ => return Err(GdbTargetError::GvaTranslateError),
    };

    // A mask of the physical address size for a virtual address
    let pa_address_mask: u64 = !0u64 >> (64 - pa_size);
    // A mask used to take the bottom 12 bits of a value this is as we have a grainsize of 9
    // asserted with our 4kb page, plus the offset of 3
    let lower_mask: u64 = 0xFFF;
    // A mask for a physical address mask with the lower 12 bits cleared
    let desc_mask: u64 = pa_address_mask & !lower_mask;

    let page_indices = [
        (gva >> (GRAIN_SIZE * 4)) & lower_mask,
        (gva >> (GRAIN_SIZE * 3)) & lower_mask,
        (gva >> (GRAIN_SIZE * 2)) & lower_mask,
        (gva >> GRAIN_SIZE) & lower_mask,
    ];

    // Transition table base register used for initial table lookup.
    // Take the bottom 48 bits from the register value.
    let mut address: u64 = get_sys_reg(TTBR1_EL1, vcpu_fd)? & pa_address_mask;
    let mut level = 0;

    while level < 4 {
        // Clear the bottom 3 bits from this address
        let pte = read_address(vmm, (address + page_indices[level]) & PTE_ADDRESS_MASK)?;
        address = pte & desc_mask;

        // If this is a valid table entry and we aren't at the end of the page tables
        // then loop again and check next level
        if (pte & 2 != 0) && (level < 3) {
            level += 1;
            continue;
        }
        break;
    }

    // Generate a mask to split between the page table entry and the GVA. The split point is
    // dependent on which level we terminate at. This is calculated by taking the level we
    // hit multiplied by the grainsize then adding the 3 offset
    let page_size = 1u64 << ((GRAIN_SIZE * (4 - level)) + 3);
    // Clear bottom bits of page size
    address &= !(page_size - 1);
    address |= gva & (page_size - 1);
    Ok(address)
}

/// Configures the kvm guest debug regs to register the hardware breakpoints
fn set_kvm_debug(
    control: u32,
    vcpu_fd: &VcpuFd,
    addrs: &[GuestAddress],
) -> Result<(), GdbTargetError> {
    let mut dbg = kvm_guest_debug {
        control,
        ..Default::default()
    };

    for (i, addr) in addrs.iter().enumerate() {
        // DBGBCR_EL1 (Debug Breakpoint Control Registers, D13.3.2):
        // bit 0: 1 (Enabled)
        // bit 1~2: 0b11 (PMC = EL1/EL0)
        // bit 5~8: 0b1111 (BAS = AArch64)
        // others: 0
        dbg.arch.dbg_bcr[i] = 0b1 | (0b11 << 1) | (0b1111 << 5);
        // DBGBVR_EL1 (Debug Breakpoint Value Registers, D13.3.3):
        // bit 2~52: VA[2:52]
        dbg.arch.dbg_bvr[i] = (!0u64 >> 11) & addr.0;
    }

    vcpu_fd.set_guest_debug(&dbg)?;

    Ok(())
}

/// Bits in a Vcpu pstate for IRQ
const IRQ_ENABLE_FLAGS: u64 = 0x80 | 0x40;
/// Register id for pstate
const PSTATE_ID: u64 = arm64_core_reg_id!(KVM_REG_SIZE_U64, offset_of!(user_pt_regs, pstate));

/// Disable IRQ interrupts to avoid getting stuck in a loop while single stepping
///
/// When GDB hits a single breakpoint and resumes it will follow the steps:
///  - Clear SW breakpoint we've hit
///  - Single step
///  - Re-insert the SW breakpoint
///  - Resume
/// However, with IRQ enabled the single step takes us into the IRQ handler so when we resume we
/// immediately hit the SW breapoint we just re-inserted getting stuck in a loop.
fn toggle_interrupts(vcpu_fd: &VcpuFd, enable: bool) -> Result<(), GdbTargetError> {
    let mut pstate = get_sys_reg(PSTATE_ID, vcpu_fd)?;

    if enable {
        pstate |= IRQ_ENABLE_FLAGS;
    } else {
        pstate &= !IRQ_ENABLE_FLAGS;
    }

    vcpu_fd.set_one_reg(PSTATE_ID, &pstate.to_le_bytes())?;

    Ok(())
}

/// Configures the Vcpu for debugging and sets the hardware breakpoints on the Vcpu
pub fn vcpu_set_debug(
    vcpu_fd: &VcpuFd,
    addrs: &[GuestAddress],
    step: bool,
) -> Result<(), GdbTargetError> {
    let mut control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW | KVM_GUESTDBG_USE_SW_BP;
    if step {
        control |= KVM_GUESTDBG_SINGLESTEP;
    }

    toggle_interrupts(vcpu_fd, step)?;
    set_kvm_debug(control, vcpu_fd, addrs)
}

/// KVM does not support injecting breakpoints on aarch64 so this is a no-op
pub fn vcpu_inject_bp(
    _vcpu_fd: &VcpuFd,
    _addrs: &[GuestAddress],
    _step: bool,
) -> Result<(), GdbTargetError> {
    Ok(())
}
/// The number of general purpose registers
const GENERAL_PURPOSE_REG_COUNT: usize = 31;
/// The number of core registers we read from the Vcpu
const CORE_REG_COUNT: usize = 33;
/// Stores the register ids of registers to be read from the Vcpu
const CORE_REG_IDS: [u64; CORE_REG_COUNT] = {
    let mut regs = [0; CORE_REG_COUNT];
    let mut idx = 0;

    let reg_offset = offset_of!(kvm_regs, regs);
    let mut off = reg_offset;
    while idx < GENERAL_PURPOSE_REG_COUNT {
        regs[idx] = arm64_core_reg_id!(KVM_REG_SIZE_U64, off);
        idx += 1;
        off += std::mem::size_of::<u64>();
    }

    regs[idx] = arm64_core_reg_id!(KVM_REG_SIZE_U64, offset_of!(user_pt_regs, sp));
    idx += 1;

    regs[idx] = arm64_core_reg_id!(KVM_REG_SIZE_U64, offset_of!(user_pt_regs, pc));
    regs
};

/// Reads the registers for the Vcpu
pub fn read_registers(vcpu_fd: &VcpuFd, regs: &mut CoreRegs) -> Result<(), GdbTargetError> {
    let mut register_vec = Aarch64RegisterVec::default();
    get_registers(vcpu_fd, &CORE_REG_IDS, &mut register_vec)?;

    let mut registers = register_vec.iter();

    for i in 0..GENERAL_PURPOSE_REG_COUNT {
        regs.x[i] = registers
            .next()
            .ok_or(GdbTargetError::ReadRegisterVecError)?
            .value();
    }

    regs.sp = registers
        .next()
        .ok_or(GdbTargetError::ReadRegisterVecError)?
        .value();

    regs.pc = registers
        .next()
        .ok_or(GdbTargetError::ReadRegisterVecError)?
        .value();

    Ok(())
}

/// Writes to the registers for the Vcpu
pub fn write_registers(vcpu_fd: &VcpuFd, regs: &CoreRegs) -> Result<(), GdbTargetError> {
    let kreg_off = offset_of!(kvm_regs, regs);
    let mut off = kreg_off;
    for i in 0..GENERAL_PURPOSE_REG_COUNT {
        vcpu_fd.set_one_reg(
            arm64_core_reg_id!(KVM_REG_SIZE_U64, off),
            &regs.x[i].to_le_bytes(),
        )?;
        off += std::mem::size_of::<u64>();
    }

    let off = offset_of!(user_pt_regs, sp);
    vcpu_fd.set_one_reg(
        arm64_core_reg_id!(KVM_REG_SIZE_U64, off + kreg_off),
        &regs.sp.to_le_bytes(),
    )?;

    let off = offset_of!(user_pt_regs, pc);
    vcpu_fd.set_one_reg(
        arm64_core_reg_id!(KVM_REG_SIZE_U64, off + kreg_off),
        &regs.pc.to_le_bytes(),
    )?;

    Ok(())
}

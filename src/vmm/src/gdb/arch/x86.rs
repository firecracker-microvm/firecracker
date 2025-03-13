// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use gdbstub_arch::x86::reg::X86_64CoreRegs as CoreRegs;
use kvm_bindings::*;
use kvm_ioctls::VcpuFd;
use vm_memory::GuestAddress;

use crate::Vmm;
use crate::gdb::target::GdbTargetError;
use crate::logger::error;

/// Sets the 9th (Global Exact Breakpoint enable) and the 10th (always 1) bits for the DR7 debug
/// control register
const X86_GLOBAL_DEBUG_ENABLE: u64 = 0b11 << 9;

/// Op code to trigger a software breakpoint in x86
const X86_SW_BP_OP: u8 = 0xCC;

/// Configures the number of bytes required for a software breakpoint
pub const SW_BP_SIZE: usize = 1;

/// The bytes stored for an x86 software breakpoint
pub const SW_BP: [u8; SW_BP_SIZE] = [X86_SW_BP_OP];

/// Gets the RIP value for a Vcpu
pub fn get_instruction_pointer(vcpu_fd: &VcpuFd) -> Result<u64, GdbTargetError> {
    let regs = vcpu_fd.get_regs()?;

    Ok(regs.rip)
}

/// Translates a virtual address according to the vCPU's current address translation mode.
pub fn translate_gva(vcpu_fd: &VcpuFd, gva: u64, _vmm: &Vmm) -> Result<u64, GdbTargetError> {
    let tr = vcpu_fd.translate_gva(gva)?;

    if tr.valid == 0 {
        return Err(GdbTargetError::GvaTranslateError);
    }

    Ok(tr.physical_address)
}

/// Configures the kvm guest debug regs to register the hardware breakpoints, the `arch.debugreg`
/// attribute is used to store the location of the hardware breakpoints, with the 8th slot being
/// used as a bitfield to track which registers are enabled and setting the
/// `X86_GLOBAL_DEBUG_ENABLE` flags. Further reading on the DR7 register can be found here:
/// https://en.wikipedia.org/wiki/X86_debug_register#DR7_-_Debug_control
fn set_kvm_debug(
    control: u32,
    vcpu_fd: &VcpuFd,
    addrs: &[GuestAddress],
) -> Result<(), GdbTargetError> {
    let mut dbg = kvm_guest_debug {
        control,
        ..Default::default()
    };

    dbg.arch.debugreg[7] = X86_GLOBAL_DEBUG_ENABLE;

    for (i, addr) in addrs.iter().enumerate() {
        dbg.arch.debugreg[i] = addr.0;
        // Set global breakpoint enable flag for the specific breakpoint number by setting the bit
        dbg.arch.debugreg[7] |= 2 << (i * 2);
    }

    vcpu_fd.set_guest_debug(&dbg)?;

    Ok(())
}

/// Configures the Vcpu for debugging and sets the hardware breakpoints on the Vcpu
pub fn vcpu_set_debug(
    vcpu_fd: &VcpuFd,
    addrs: &[GuestAddress],
    step: bool,
) -> Result<(), GdbTargetError> {
    let mut control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW_BP | KVM_GUESTDBG_USE_SW_BP;
    if step {
        control |= KVM_GUESTDBG_SINGLESTEP;
    }

    set_kvm_debug(control, vcpu_fd, addrs)
}

/// Injects a BP back into the guest kernel for it to handle, this is particularly useful for the
/// kernels selftesting which can happen during boot.
pub fn vcpu_inject_bp(
    vcpu_fd: &VcpuFd,
    addrs: &[GuestAddress],
    step: bool,
) -> Result<(), GdbTargetError> {
    let mut control = KVM_GUESTDBG_ENABLE
        | KVM_GUESTDBG_USE_HW_BP
        | KVM_GUESTDBG_USE_SW_BP
        | KVM_GUESTDBG_INJECT_BP;

    if step {
        control |= KVM_GUESTDBG_SINGLESTEP;
    }

    set_kvm_debug(control, vcpu_fd, addrs)
}

/// Reads the registers for the Vcpu
pub fn read_registers(vcpu_fd: &VcpuFd, regs: &mut CoreRegs) -> Result<(), GdbTargetError> {
    let cpu_regs = vcpu_fd.get_regs()?;

    regs.regs[0] = cpu_regs.rax;
    regs.regs[1] = cpu_regs.rbx;
    regs.regs[2] = cpu_regs.rcx;
    regs.regs[3] = cpu_regs.rdx;
    regs.regs[4] = cpu_regs.rsi;
    regs.regs[5] = cpu_regs.rdi;
    regs.regs[6] = cpu_regs.rbp;
    regs.regs[7] = cpu_regs.rsp;

    regs.regs[8] = cpu_regs.r8;
    regs.regs[9] = cpu_regs.r9;
    regs.regs[10] = cpu_regs.r10;
    regs.regs[11] = cpu_regs.r11;
    regs.regs[12] = cpu_regs.r12;
    regs.regs[13] = cpu_regs.r13;
    regs.regs[14] = cpu_regs.r14;
    regs.regs[15] = cpu_regs.r15;

    regs.rip = cpu_regs.rip;
    regs.eflags = u32::try_from(cpu_regs.rflags).map_err(|e| {
        error!("Error {e:?} converting rflags to u32");
        GdbTargetError::RegFlagConversionError
    })?;

    Ok(())
}
/// Writes to the registers for the Vcpu
pub fn write_registers(vcpu_fd: &VcpuFd, regs: &CoreRegs) -> Result<(), GdbTargetError> {
    let new_regs = kvm_regs {
        rax: regs.regs[0],
        rbx: regs.regs[1],
        rcx: regs.regs[2],
        rdx: regs.regs[3],
        rsi: regs.regs[4],
        rdi: regs.regs[5],
        rbp: regs.regs[6],
        rsp: regs.regs[7],

        r8: regs.regs[8],
        r9: regs.regs[9],
        r10: regs.regs[10],
        r11: regs.regs[11],
        r12: regs.regs[12],
        r13: regs.regs[13],
        r14: regs.regs[14],
        r15: regs.regs[15],

        rip: regs.rip,
        rflags: regs.eflags as u64,
    };

    Ok(vcpu_fd.set_regs(&new_regs)?)
}

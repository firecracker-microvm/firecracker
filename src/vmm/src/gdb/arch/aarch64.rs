// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use gdbstub_arch::aarch64::reg::AArch64CoreRegs as CoreRegs;
use kvm_ioctls::VcpuFd;
use vm_memory::GuestAddress;

use crate::gdb::target::GdbTargetError;

/// Configures the number of bytes required for a software breakpoint
pub const SW_BP_SIZE: usize = 1;

/// The bytes stored for a software breakpoint
pub const SW_BP: [u8; SW_BP_SIZE] = [0];

/// Gets the RIP value for a Vcpu
pub fn get_instruction_pointer(_vcpu_fd: &VcpuFd) -> Result<u64, GdbTargetError> {
    unimplemented!()
}

/// Translates a virtual address according to the vCPU's current address translation mode.
pub fn translate_gva(_vcpu_fd: &VcpuFd, _gva: u64) -> Result<u64, GdbTargetError> {
    unimplemented!()
}

/// Configures the kvm guest debug regs to register the hardware breakpoints
fn set_kvm_debug(
    _control: u32,
    _vcpu_fd: &VcpuFd,
    _addrs: &[GuestAddress],
) -> Result<(), GdbTargetError> {
    unimplemented!()
}

/// Configures the Vcpu for debugging and sets the hardware breakpoints on the Vcpu
pub fn vcpu_set_debug(
    _vcpu_fd: &VcpuFd,
    _addrs: &[GuestAddress],
    _step: bool,
) -> Result<(), GdbTargetError> {
    unimplemented!()
}

/// Injects a BP back into the guest kernel for it to handle, this is particularly useful for the
/// kernels selftesting which can happen during boot.
pub fn vcpu_inject_bp(
    _vcpu_fd: &VcpuFd,
    _addrs: &[GuestAddress],
    _step: bool,
) -> Result<(), GdbTargetError> {
    unimplemented!()
}

/// Reads the registers for the Vcpu
pub fn read_registers(_vcpu_fd: &VcpuFd, _regs: &mut CoreRegs) -> Result<(), GdbTargetError> {
    unimplemented!()
}

/// Writes to the registers for the Vcpu
pub fn write_registers(_vcpu_fd: &VcpuFd, _regs: &CoreRegs) -> Result<(), GdbTargetError> {
    unimplemented!()
}

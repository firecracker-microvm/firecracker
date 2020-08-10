// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::{
    fmt::{Display, Formatter},
    result,
};

use crate::vstate::{vcpu::VcpuEmulation, vm::Vm};
use kvm_ioctls::*;
use logger::{error, Metric, METRICS};
use vm_memory::{Address, GuestAddress, GuestMemoryMmap};

/// Errors associated with the wrappers over KVM ioctls.
#[derive(Debug)]
pub enum Error {
    /// Error configuring the general purpose aarch64 registers.
    REGSConfiguration(arch::aarch64::regs::Error),
    /// Operation not supported.
    UnsupportedAction(&'static str),
    /// Cannot open the VCPU file descriptor.
    VcpuFd(kvm_ioctls::Error),
    /// Error doing Vcpu Init on Arm.
    VcpuInit(kvm_ioctls::Error),
    /// Error getting the Vcpu preferred target on Arm.
    VcpuPreferredTarget(kvm_ioctls::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::Error::*;

        match self {
            REGSConfiguration(e) => write!(
                f,
                "Error configuring the general purpose registers: {:?}",
                e
            ),
            UnsupportedAction(msg) => {
                write!(f, "{} is not yet supported on this architecture", msg)
            }
            VcpuFd(e) => write!(f, "Error in opening the VCPU file descriptor: {}", e),
            VcpuInit(e) => write!(f, "Error initializing the vcpu: {}", e),
            VcpuPreferredTarget(e) => {
                write!(f, "Error retrieving the vcpu preferred target: {}", e)
            }
        }
    }
}

type Result<T> = result::Result<T, Error>;

/// A wrapper around creating and using a kvm aarch64 vcpu.
pub struct KvmVcpu {
    pub index: u8,
    pub fd: VcpuFd,

    pub mmio_bus: Option<devices::Bus>,

    mpidr: u64,
}

impl KvmVcpu {
    /// Constructs a new kvm vcpu with arch specific functionality.
    ///
    /// # Arguments
    ///
    /// * `id` - Represents the CPU number between [0, max vcpus).
    /// * `vm` - The vm to which this vcpu will get attached.
    pub fn new(index: u8, vm: &Vm) -> Result<Self> {
        let kvm_vcpu = vm.fd().create_vcpu(index).map_err(Error::VcpuFd)?;

        Ok(KvmVcpu {
            index,
            fd: kvm_vcpu,
            mmio_bus: None,
            mpidr: 0,
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
    /// * `vm_fd` - The kvm `VmFd` for this microvm.
    /// * `guest_mem` - The guest memory used by this microvm.
    /// * `kernel_load_addr` - Offset from `guest_mem` at which the kernel is loaded.
    pub fn configure(
        &mut self,
        vm_fd: &VmFd,
        guest_mem: &GuestMemoryMmap,
        kernel_load_addr: GuestAddress,
    ) -> Result<()> {
        let mut kvi: kvm_bindings::kvm_vcpu_init = kvm_bindings::kvm_vcpu_init::default();

        // This reads back the kernel's preferred target type.
        vm_fd
            .get_preferred_target(&mut kvi)
            .map_err(Error::VcpuPreferredTarget)?;
        // We already checked that the capability is supported.
        kvi.features[0] |= 1 << kvm_bindings::KVM_ARM_VCPU_PSCI_0_2;
        // Non-boot cpus are powered off initially.
        if self.index > 0 {
            kvi.features[0] |= 1 << kvm_bindings::KVM_ARM_VCPU_POWER_OFF;
        }

        self.fd.vcpu_init(&kvi).map_err(Error::VcpuInit)?;
        arch::aarch64::regs::setup_boot_regs(
            &self.fd,
            self.index,
            kernel_load_addr.raw_value(),
            guest_mem,
        )
        .map_err(Error::REGSConfiguration)?;

        self.mpidr = arch::aarch64::regs::read_mpidr(&self.fd).map_err(Error::REGSConfiguration)?;

        Ok(())
    }

    /// Save the KVM internal state.
    pub fn save_state(&self) -> Result<VcpuState> {
        Err(Error::UnsupportedAction("Saving the state"))
    }

    /// Use provided state to populate KVM internal state.
    pub fn restore_state(&self, _state: &VcpuState) -> Result<()> {
        Err(Error::UnsupportedAction("Restoring the state"))
    }

    /// Runs the vCPU in KVM context and handles the kvm exit reason.
    ///
    /// Returns error or enum specifying whether emulation was handled or interrupted.
    pub fn run_arch_emulation(&self, exit: VcpuExit) -> super::Result<VcpuEmulation> {
        METRICS.vcpu.failures.inc();
        // TODO: Are we sure we want to finish running a vcpu upon
        // receiving a vm exit that is not necessarily an error?
        error!("Unexpected exit reason on vcpu run: {:?}", exit);
        Err(super::Error::UnhandledKvmExit(format!("{:?}", exit)))
    }
}

/// Structure holding VCPU kvm state.
#[derive(Clone, Default)]
pub struct VcpuState {}

#[cfg(test)]
mod tests {
    use std::os::unix::io::AsRawFd;

    use super::*;
    use crate::vstate::vm::{tests::setup_vm, Vm};
    use vm_memory::GuestMemoryMmap;

    fn setup_vcpu(mem_size: usize) -> (Vm, KvmVcpu, GuestMemoryMmap) {
        let (mut vm, vm_mem) = setup_vm(mem_size);
        let vcpu = KvmVcpu::new(0, &vm).unwrap();
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
            "Error in opening the VCPU file descriptor: Bad file descriptor (os error 9)"
                .to_string()
        );
    }

    #[test]
    fn test_configure_vcpu() {
        let (vm, mut vcpu, vm_mem) = setup_vcpu(0x10000);

        assert!(vcpu
            .configure(&vm.fd(), &vm_mem, GuestAddress(arch::get_kernel_start()),)
            .is_ok());

        unsafe { libc::close(vm.fd().as_raw_fd()) };

        let err = vcpu.configure(&vm.fd(), &vm_mem, GuestAddress(arch::get_kernel_start()));
        assert!(err.is_err());
        assert_eq!(
            err.err().unwrap().to_string(),
            "Error retrieving the vcpu preferred target: Bad file descriptor (os error 9)"
                .to_string()
        );

        let (vm, mut vcpu, vm_mem) = setup_vcpu(0x10000);
        unsafe { libc::close(vcpu.fd.as_raw_fd()) };
        let err = vcpu.configure(&vm.fd(), &vm_mem, GuestAddress(arch::get_kernel_start()));
        assert!(err.is_err());
        assert_eq!(
            err.err().unwrap().to_string(),
            "Error initializing the vcpu: Bad file descriptor (os error 9)".to_string()
        );
    }

    #[test]
    fn test_vcpu_save_restore_state() {
        let (_vm, vcpu, _mem) = setup_vcpu(0x1000);

        let res = vcpu.save_state();
        assert!(res.is_err());
        assert_eq!(
            res.err().unwrap().to_string(),
            "Saving the state is not yet supported on this architecture".to_string()
        );

        let res = vcpu.restore_state(&VcpuState::default());
        assert!(res.is_err());
        assert_eq!(
            res.err().unwrap().to_string(),
            "Restoring the state is not yet supported on this architecture".to_string()
        );
    }
}

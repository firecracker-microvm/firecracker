// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

extern crate devices;
extern crate logger;
extern crate sys_util;
extern crate x86_64;

use std::result;

use super::KvmContext;
use cpuid::{c3_template, filter_cpuid, t2_template};
use kvm::*;
use logger::{LogOption, LOGGER};
use memory_model::{GuestAddress, GuestMemory, GuestMemoryError};
use sys_util::EventFd;
use vmm_config::machine_config::{CpuFeaturesTemplate, VmConfig};
use x86_64::{interrupts, regs};

pub const KVM_TSS_ADDRESS: usize = 0xfffbd000;
const KVM_MEM_LOG_DIRTY_PAGES: u32 = 0x1;

/// Errors associated with the wrappers over KVM ioctls.
#[derive(Debug)]
pub enum Error {
    /// A call to cpuid instruction failed.
    CpuId(cpuid::Error),
    /// Invalid guest memory configuration.
    GuestMemory(GuestMemoryError),
    /// Hyperthreading flag is not initialized.
    HTNotInitialized,
    /// vCPU count is not initialized.
    VcpuCountNotInitialized,
    /// Cannot open the VM file descriptor.
    VmFd(sys_util::Error),
    /// Cannot open the VCPU file descriptor.
    VcpuFd(sys_util::Error),
    /// Cannot configure the microvm.
    VmSetup(sys_util::Error),
    /// Cannot run the VCPUs.
    VcpuRun(sys_util::Error),
    /// The call to KVM_SET_CPUID2 failed.
    SetSupportedCpusFailed(sys_util::Error),
    /// The number of configured slots is bigger than the maximum reported by KVM.
    NotEnoughMemorySlots,
    /// Cannot set the local interruption due to bad configuration.
    LocalIntConfiguration(interrupts::Error),
    /// Cannot set the memory regions.
    SetUserMemoryRegion(sys_util::Error),
    /// Error configuring the MSR registers
    MSRSConfiguration(regs::Error),
    /// Error configuring the general purpose registers
    REGSConfiguration(regs::Error),
    /// Error configuring the special registers
    SREGSConfiguration(regs::Error),
    /// Error configuring the floating point related registers
    FPUConfiguration(regs::Error),
    /// Cannot configure the IRQ.
    Irq(sys_util::Error),
}
pub type Result<T> = result::Result<T, Error>;

impl ::std::convert::From<sys_util::Error> for Error {
    fn from(e: sys_util::Error) -> Error {
        Error::SetUserMemoryRegion(e)
    }
}

/// A wrapper around creating and using a VM.
pub struct Vm {
    fd: VmFd,
    guest_mem: Option<GuestMemory>,
}

impl Vm {
    /// Constructs a new `Vm` using the given `Kvm` instance.
    pub fn new(kvm: &Kvm) -> Result<Self> {
        //create fd for interacting with kvm-vm specific functions
        let vm_fd = kvm.create_vm().map_err(Error::VmFd)?;

        Ok(Vm {
            fd: vm_fd,
            guest_mem: None,
        })
    }

    /// Initializes the guest memory. Currently this is x86 specific
    /// because of the TSS address setup.
    pub fn memory_init(&mut self, guest_mem: GuestMemory, kvm_context: &KvmContext) -> Result<()> {
        if guest_mem.num_regions() > kvm_context.max_memslots() {
            return Err(Error::NotEnoughMemorySlots);
        }
        guest_mem.with_regions(|index, guest_addr, size, host_addr| {
            info!("Guest memory starts at {:x?}", host_addr);

            let flags = if LOGGER.flags() & LogOption::LogDirtyPages as usize > 0 {
                KVM_MEM_LOG_DIRTY_PAGES
            } else {
                0
            };
            // Safe because the guest regions are guaranteed not to overlap.
            self.fd.set_user_memory_region(
                index as u32,
                guest_addr.offset() as u64,
                size as u64,
                host_addr as u64,
                flags,
            )
        })?;
        self.guest_mem = Some(guest_mem);

        let tss_addr = GuestAddress(KVM_TSS_ADDRESS);
        self.fd
            .set_tss_address(tss_addr.offset())
            .map_err(Error::VmSetup)?;

        Ok(())
    }

    /// This function creates the irq chip and adds 2 interrupt events to the IRQ.
    pub fn setup_irqchip(&self, com_evt_1_3: &EventFd, com_evt_2_4: &EventFd) -> Result<()> {
        self.fd.create_irq_chip().map_err(Error::VmSetup)?;

        self.fd.register_irqfd(com_evt_1_3, 4).map_err(Error::Irq)?;
        self.fd.register_irqfd(com_evt_2_4, 3).map_err(Error::Irq)?;

        Ok(())
    }

    /// Creates an in-kernel device model for the PIT.
    pub fn create_pit(&self) -> Result<()> {
        self.fd.create_pit2().map_err(Error::VmSetup)?;
        Ok(())
    }

    /// Gets a reference to the guest memory owned by this VM.
    ///
    /// Note that `GuestMemory` does not include any device memory that may have been added after
    /// this VM was constructed.
    pub fn get_memory(&self) -> Option<&GuestMemory> {
        self.guest_mem.as_ref()
    }

    /// Gets a reference to the kvm file descriptor owned by this VM.
    ///
    pub fn get_fd(&self) -> &VmFd {
        &self.fd
    }
}

/// A wrapper around creating and using a kvm-based VCPU.
pub struct Vcpu {
    cpuid: CpuId,
    fd: VcpuFd,
    id: u8,
}

impl Vcpu {
    /// Constructs a new VCPU for `vm`.
    ///
    /// The `id` argument is the CPU number between [0, max vcpus).
    pub fn new(id: u8, vm: &Vm) -> Result<Self> {
        let kvm_vcpu = vm.fd.create_vcpu(id).map_err(Error::VcpuFd)?;
        // Initially the cpuid per vCPU is the one supported by this VM
        Ok(Vcpu {
            fd: kvm_vcpu,
            cpuid: vm.fd.get_supported_cpuid(),
            id,
        })
    }

    /// /// Configures the vcpu and should be called once per vcpu from the vcpu's thread.
    ///
    /// # Arguments
    ///
    /// * `kernel_load_offset` - Offset from `guest_mem` at which the kernel starts.
    /// nr cpus is required for checking populating the kvm_cpuid2 entry for ebx and edx registers
    pub fn configure(
        &mut self,
        machine_config: &VmConfig,
        kernel_start_addr: GuestAddress,
        vm: &Vm,
    ) -> Result<()> {
        // the MachineConfiguration has defaults for ht_enabled and vcpu_count.
        filter_cpuid(
            self.id,
            machine_config
                .vcpu_count
                .ok_or(Error::VcpuCountNotInitialized)?,
            machine_config.ht_enabled.ok_or(Error::HTNotInitialized)?,
            &mut self.cpuid,
        ).map_err(|e| Error::CpuId(e))?;
        match machine_config.cpu_template {
            Some(template) => match template {
                CpuFeaturesTemplate::T2 => {
                    t2_template::set_cpuid_entries(self.cpuid.mut_entries_slice())
                }
                CpuFeaturesTemplate::C3 => {
                    c3_template::set_cpuid_entries(self.cpuid.mut_entries_slice())
                }
            },
            None => (),
        }

        self.fd
            .set_cpuid2(&self.cpuid)
            .map_err(Error::SetSupportedCpusFailed)?;

        regs::setup_msrs(&self.fd).map_err(Error::MSRSConfiguration)?;
        // Safe to unwrap because this method is called after the VM is configured
        let vm_memory = vm
            .get_memory()
            .ok_or(Error::GuestMemory(GuestMemoryError::MemoryNotInitialized))?;
        regs::setup_regs(
            &self.fd,
            kernel_start_addr.offset() as u64,
            x86_64::layout::BOOT_STACK_POINTER as u64,
            x86_64::layout::ZERO_PAGE_START as u64,
        ).map_err(Error::REGSConfiguration)?;
        regs::setup_fpu(&self.fd).map_err(Error::FPUConfiguration)?;
        regs::setup_sregs(vm_memory, &self.fd).map_err(Error::SREGSConfiguration)?;
        interrupts::set_lint(&self.fd).map_err(Error::LocalIntConfiguration)?;
        Ok(())
    }

    /// Runs the VCPU until it exits, returning the reason.
    ///
    /// Note that the state of the VCPU and associated VM must be setup first for this to do
    /// anything useful.
    pub fn run(&self) -> Result<VcpuExit> {
        match self.fd.run() {
            Ok(v) => Ok(v),
            Err(e) => return Err(Error::VcpuRun(<sys_util::Error>::new(e.errno()))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::unix::io::AsRawFd;

    #[test]
    fn create_vm() {
        let kvm_fd = Kvm::new().unwrap();
        let kvm = KvmContext::new(Some(kvm_fd.as_raw_fd())).unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x10000)]).unwrap();
        let mut vm = Vm::new(&kvm_fd).expect("new vm failed");
        assert!(vm.memory_init(gm, &kvm).is_ok());
    }

    #[test]
    fn get_memory() {
        let kvm_fd = Kvm::new().unwrap();
        let kvm = KvmContext::new(Some(kvm_fd.as_raw_fd())).unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x1000)]).unwrap();
        let mut vm = Vm::new(&kvm_fd).expect("new vm failed");
        assert!(vm.memory_init(gm, &kvm).is_ok());
        let obj_addr = GuestAddress(0xf0);
        vm.get_memory()
            .unwrap()
            .write_obj_at_addr(67u8, obj_addr)
            .unwrap();
        let read_val: u8 = vm
            .get_memory()
            .unwrap()
            .read_obj_from_addr(obj_addr)
            .unwrap();
        assert_eq!(read_val, 67u8);
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[test]
    fn test_configure_vcpu() {
        let kvm_fd = Kvm::new().unwrap();
        let kvm = KvmContext::new(Some(kvm_fd.as_raw_fd())).unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x10000)]).unwrap();
        let mut vm = Vm::new(&kvm_fd).expect("new vm failed");
        assert!(vm.memory_init(gm, &kvm).is_ok());
        let dummy_eventfd_1 = EventFd::new().unwrap();
        let dummy_eventfd_2 = EventFd::new().unwrap();

        vm.setup_irqchip(&dummy_eventfd_1, &dummy_eventfd_2)
            .unwrap();
        vm.create_pit().unwrap();

        let mut vcpu = Vcpu::new(1, &vm).unwrap();
        let vm_config = VmConfig::default();
        assert!(vcpu.configure(&vm_config, GuestAddress(0), &vm).is_ok());

        // Test configure while using the T2 template.
        let mut vm_config = VmConfig::default();
        vm_config.cpu_template = Some(CpuFeaturesTemplate::T2);
        assert!(vcpu.configure(&vm_config, GuestAddress(0), &vm).is_ok());

        // Test configure while using the C3 template.
        let mut vm_config = VmConfig::default();
        vm_config.cpu_template = Some(CpuFeaturesTemplate::C3);
        assert!(vcpu.configure(&vm_config, GuestAddress(0), &vm).is_ok());
    }

    #[test]
    fn not_enough_mem_slots() {
        let kvm_fd = Kvm::new().unwrap();
        let mut vm = Vm::new(&kvm_fd).expect("new vm failed");

        let kvm = KvmContext {
            kvm: kvm_fd,
            max_memslots: 1,
        };
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let gm = GuestMemory::new(&vec![(start_addr1, 0x1000), (start_addr2, 0x1000)]).unwrap();

        assert!(vm.memory_init(gm, &kvm).is_err());
    }

    #[test]
    fn run_code() {
        use std::io::{self, Write};
        // This example based on https://lwn.net/Articles/658511/
        let code = [
            0xba, 0xf8, 0x03, /* mov $0x3f8, %dx */
            0x00, 0xd8, /* add %bl, %al */
            0x04, '0' as u8, /* add $'0', %al */
            0xee,      /* out %al, (%dx) */
            0xb0, '\n' as u8, /* mov $'\n', %al */
            0xee,       /* out %al, (%dx) */
            0xf4,       /* hlt */
        ];

        let mem_size = 0x1000;
        let load_addr = GuestAddress(0x1000);
        let mem = GuestMemory::new(&vec![(load_addr, mem_size)]).unwrap();

        let kvm_fd = Kvm::new().expect("new kvm failed");
        let kvm = KvmContext::new(Some(kvm_fd.as_raw_fd())).unwrap();
        let mut vm = Vm::new(&kvm_fd).expect("new vm failed");
        assert!(vm.memory_init(mem, &kvm).is_ok());
        vm.get_memory()
            .unwrap()
            .write_slice_at_addr(&code, load_addr)
            .expect("Writing code to memory failed.");

        let vcpu = Vcpu::new(0, &mut vm).expect("new vcpu failed");

        let mut vcpu_sregs = vcpu.fd.get_sregs().expect("get sregs failed");
        assert_ne!(vcpu_sregs.cs.base, 0);
        assert_ne!(vcpu_sregs.cs.selector, 0);
        vcpu_sregs.cs.base = 0;
        vcpu_sregs.cs.selector = 0;
        vcpu.fd.set_sregs(&vcpu_sregs).expect("set sregs failed");

        let mut vcpu_regs = vcpu.fd.get_regs().expect("get regs failed");
        vcpu_regs.rip = 0x1000;
        vcpu_regs.rax = 2;
        vcpu_regs.rbx = 3;
        vcpu_regs.rflags = 2;
        vcpu.fd.set_regs(&vcpu_regs).expect("set regs failed");

        loop {
            match vcpu.run().expect("run failed") {
                VcpuExit::IoOut(0x3f8, data) => {
                    assert_eq!(data.len(), 1);
                    io::stdout().write(data).unwrap();
                }
                VcpuExit::Hlt => {
                    io::stdout().write(b"KVM_EXIT_HLT\n").unwrap();
                    break;
                }
                r => panic!("unexpected exit reason: {:?}", r),
            }
        }
    }
}

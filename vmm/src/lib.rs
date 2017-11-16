extern crate sys_util;
extern crate kvm_sys;
extern crate kvm;
extern crate kernel_loader;
extern crate x86_64;
extern crate clap;
extern crate devices;

pub mod machine;

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, stdout, Write};
use std::sync::{Arc, Mutex};
use kvm::*;
use kvm_sys::kvm_regs;
use sys_util::{EventFd, GuestAddress, GuestMemory};
use machine::MachineCfg;

const KERNEL_START_OFFSET: usize = 0x200000;
const CMDLINE_OFFSET: usize = 0x20000;

pub enum Error {
    ConfigureSystem(x86_64::Error),
    EventFd(sys_util::Error),
    GuestMemory(sys_util::GuestMemoryError),
    Kernel(std::io::Error),
    KernelLoader(kernel_loader::Error),
    Kvm(sys_util::Error),
    Vcpu(sys_util::Error),
    Vm(sys_util::Error),
}

impl std::convert::From<kernel_loader::Error> for Error {
    fn from(e: kernel_loader::Error) -> Error {
        Error::KernelLoader(e)
    }
}

impl std::convert::From<x86_64::Error> for Error {
    fn from(e: x86_64::Error) -> Error {
        Error::ConfigureSystem(e)
    }
}

type Result<T> = std::result::Result<T, Error>;

pub fn boot_kernel(cfg: &MachineCfg) -> Result<()> {
    // FIXME branciog@ do not hardcode the vm mem size
    // Hardcoding the vm memory size to 128MB
    let mem_size = 128 << 20;
    let arch_mem_regions = x86_64::arch_memory_regions(mem_size);

    let mut kernel_file;
    match cfg.kernel_path {
        Some(ref kernel_path) => {
            kernel_file = File::open(kernel_path.as_path())
                    .map_err(Error::Kernel)?
        },
        None => {
            return Err(Error::Kernel(
                    io::Error::new(io::ErrorKind::NotFound,
                                   "missing kernel path")))
        }
    }

    let cmdline: CString = match cfg.kernel_cmdline {
        Some(ref v) => CString::new(v.as_bytes()).unwrap(),
        _ => return Err(Error::Kernel(
                io::Error::new(io::ErrorKind::NotFound,
                               "missing kernel cmdline")))
    };
    let cmdline: &CStr = &cmdline;
    let vcpu_count = 1;

    let kernel_start_addr = GuestAddress(KERNEL_START_OFFSET);
    let cmdline_addr = GuestAddress(CMDLINE_OFFSET);

    let guest_mem = GuestMemory::new(&arch_mem_regions)
            .map_err(Error::GuestMemory)?;

    let kvm = Kvm::new().map_err(Error::Kvm)?;
    let vm = Vm::new(&kvm, guest_mem).map_err(Error::Vm)?;

    let tss_addr = GuestAddress(0xfffbd000);
    vm.set_tss_addr(tss_addr).map_err(Error::Vm)?;
    vm.create_pit().map_err(Error::Vm)?;
    vm.create_irq_chip().map_err(Error::Vm)?;

    kernel_loader::load_kernel(vm.get_memory(), kernel_start_addr,
                               &mut kernel_file)?;
    kernel_loader::load_cmdline(vm.get_memory(), cmdline_addr, cmdline)?;

    x86_64::configure_system(vm.get_memory(),
                             kernel_start_addr,
                             cmdline_addr,
                             cmdline.to_bytes().len() + 1,
                             vcpu_count as u8)?;


    let vcpu = Vcpu::new(0, &kvm, &vm).map_err(Error::Vcpu)?;

    x86_64::configure_vcpu(vm.get_memory(),
                           kernel_start_addr,
                           &kvm,
                           &vcpu,
                           0,
                           vcpu_count as u64)?;

    let mut io_bus = devices::Bus::new();
    let com_evt = EventFd::new().map_err(Error::EventFd)?;
    let stdio_serial =
        Arc::new(Mutex::new(
                    devices::Serial::new_out(com_evt, Box::new(stdout()))));
    io_bus.insert(stdio_serial, 0x3f8, 0x8).unwrap();

    loop {
        match vcpu.run().map_err(Error::Vcpu)? {
            VcpuExit::IoIn(_addr, _data) => {
                io_bus.read(_addr as u64, _data);
            },
            VcpuExit::IoOut(_addr, _data) => {
                io_bus.write(_addr as u64, _data);
            },
            VcpuExit::MmioRead(_addr, _data) => {
                //mmio_bus.read(addr, data);
            },
            VcpuExit::MmioWrite(_addr, _data) => {
                //mmio_bus.write(addr, data);
            },
            VcpuExit::Hlt => {
                println!("KVM_EXIT_HLT");
                break;
            },
            VcpuExit::Shutdown => {
                println!("KVM_EXIT_SHUTDOWN");
                break;
            },
            r => {
                println!("unexpected exit reason: {:?}", r);
                break;
            }
        }
    }

    Ok(())
}



pub fn run_x86_code() {
    // This example based on https://lwn.net/Articles/658511/
    let code = [
        0xba, 0xf8, 0x03, /* mov $0x3f8, %dx */
        0x00, 0xd8,       /* add %bl, %al */
        0x04, '0' as u8,  /* add $'0', %al */
        0xee,             /* out %al, (%dx) */
        0xb0, '\n' as u8, /* mov $'\n', %al */
        0xee,             /* out %al, (%dx) */
        0xf4,             /* hlt */
    ];

    let mem_size = 0x1000;
    let load_addr = GuestAddress(0x1000);
    let mem = GuestMemory::new(&vec![(load_addr, mem_size)]).unwrap();

    let kvm = Kvm::new().expect("new kvm failed");
    let vm = Vm::new(&kvm, mem).expect("new vm failed");
    let vcpu = Vcpu::new(0, &kvm, &vm).expect("new vcpu failed");

    vm.get_memory()
        .write_slice_at_addr(&code, load_addr)
        .expect("Writing code to memory failed.");

    let mut vcpu_sregs = vcpu.get_sregs().expect("get sregs failed");
    assert_ne!(vcpu_sregs.cs.base, 0);
    assert_ne!(vcpu_sregs.cs.selector, 0);
    vcpu_sregs.cs.base = 0;
    vcpu_sregs.cs.selector = 0;
    vcpu.set_sregs(&vcpu_sregs).expect("set sregs failed");

    let mut vcpu_regs: kvm_regs = unsafe { std::mem::zeroed() };
    vcpu_regs.rip = 0x1000;
    vcpu_regs.rax = 2;
    vcpu_regs.rbx = 2;
    vcpu_regs.rflags = 2;
    vcpu.set_regs(&vcpu_regs).expect("set regs failed");

    loop {
        match vcpu.run().expect("run failed") {
            VcpuExit::IoOut(0x3f8, data) => {
                assert_eq!(data.len(), 1);
                io::stdout().write(data).unwrap();
            },
            VcpuExit::Hlt => {
                io::stdout().write(b"KVM_EXIT_HLT\n").unwrap();
                break
            },
            r => panic!("unexpected exit reason: {:?}", r),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_code() {
        run_x86_code();
    }
}

extern crate libc;
#[macro_use]
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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::thread::JoinHandle;
use kvm::*;
use kvm_sys::kvm_regs;
use sys_util::{register_signal_handler, EventFd, GuestAddress, GuestMemory, Killable, Pollable,
               Poller, Terminal};
use machine::MachineCfg;

const KERNEL_START_OFFSET: usize = 0x200000;
const CMDLINE_OFFSET: usize = 0x20000;

#[derive(Debug)]
pub enum Error {
    ConfigureSystem(x86_64::Error),
    EventFd(sys_util::Error),
    GuestMemory(sys_util::GuestMemoryError),
    Irq(sys_util::Error),
    Kernel(std::io::Error),
    KernelLoader(kernel_loader::Error),
    Kvm(sys_util::Error),
    Vcpu(sys_util::Error),
    VcpuSpawn(std::io::Error),
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
            kernel_file = File::open(kernel_path.as_path()).map_err(Error::Kernel)?
        }
        None => {
            return Err(Error::Kernel(io::Error::new(
                io::ErrorKind::NotFound,
                "missing kernel path",
            )))
        }
    }

    let cmdline: CString = match cfg.kernel_cmdline {
        Some(ref v) => CString::new(v.as_bytes()).unwrap(),
        _ => {
            return Err(Error::Kernel(io::Error::new(
                io::ErrorKind::NotFound,
                "missing kernel cmdline",
            )))
        }
    };
    let cmdline: &CStr = &cmdline;
    let vcpu_count = 1;

    let kernel_start_addr = GuestAddress(KERNEL_START_OFFSET);
    let cmdline_addr = GuestAddress(CMDLINE_OFFSET);

    let guest_mem = GuestMemory::new(&arch_mem_regions).map_err(
        Error::GuestMemory,
    )?;

    let kvm = Kvm::new().map_err(Error::Kvm)?;
    let vm = Vm::new(&kvm, guest_mem).map_err(Error::Vm)?;

    let tss_addr = GuestAddress(0xfffbd000);
    vm.set_tss_addr(tss_addr).map_err(Error::Vm)?;
    vm.create_pit().map_err(Error::Vm)?;
    vm.create_irq_chip().map_err(Error::Vm)?;

    kernel_loader::load_kernel(vm.get_memory(), kernel_start_addr, &mut kernel_file)?;
    kernel_loader::load_cmdline(vm.get_memory(), cmdline_addr, cmdline)?;

    x86_64::configure_system(
        vm.get_memory(),
        kernel_start_addr,
        cmdline_addr,
        cmdline.to_bytes().len() + 1,
        vcpu_count as u8,
    )?;

    let mut io_bus = devices::Bus::new();
    let com_evt_1_3 = EventFd::new().map_err(Error::EventFd)?;
    let com_evt_2_4 = EventFd::new().map_err(Error::EventFd)?;
    let stdio_serial = Arc::new(Mutex::new(devices::Serial::new_out(
        com_evt_1_3.try_clone().map_err(Error::EventFd)?,
        Box::new(stdout()),
    )));

    io_bus.insert(stdio_serial.clone(), 0x3f8, 0x8).unwrap();
    io_bus
        .insert(
            Arc::new(Mutex::new(devices::Serial::new_sink(
                com_evt_2_4.try_clone().map_err(Error::EventFd)?,
            ))),
            0x2f8,
            0x8,
        )
        .unwrap();
    io_bus
        .insert(
            Arc::new(Mutex::new(devices::Serial::new_sink(
                com_evt_1_3.try_clone().map_err(Error::EventFd)?,
            ))),
            0x3e8,
            0x8,
        )
        .unwrap();
    io_bus
        .insert(
            Arc::new(Mutex::new(devices::Serial::new_sink(
                com_evt_2_4.try_clone().map_err(Error::EventFd)?,
            ))),
            0x2e8,
            0x8,
        )
        .unwrap();

    vm.register_irqfd(&com_evt_1_3, 4).map_err(Error::Irq)?;
    vm.register_irqfd(&com_evt_2_4, 3).map_err(Error::Irq)?;

    let exit_evt = EventFd::new().map_err(Error::EventFd)?;
    io_bus
        .insert(
            Arc::new(Mutex::new(devices::I8042Device::new(
                exit_evt.try_clone().map_err(Error::EventFd)?,
            ))),
            0x064,
            0x1,
        )
        .unwrap();

    let mut vcpu_handles = Vec::with_capacity(vcpu_count as usize);
    let vcpu_thread_barrier = Arc::new(Barrier::new((vcpu_count + 1) as usize));
    let kill_signaled = Arc::new(AtomicBool::new(false));

    for cpu_id in 0..vcpu_count {
        let io_bus = io_bus.clone();
        let kill_signaled = kill_signaled.clone();
        let vcpu_thread_barrier = vcpu_thread_barrier.clone();
        let vcpu_exit_evt = exit_evt.try_clone().map_err(Error::EventFd)?;

        let vcpu = Vcpu::new(cpu_id as libc::c_ulong, &kvm, &vm).map_err(
            Error::Vcpu,
        )?;
        x86_64::configure_vcpu(
            vm.get_memory(),
            kernel_start_addr,
            &kvm,
            &vcpu,
            cpu_id as u64,
            vcpu_count as u64,
        )?;
        vcpu_handles.push(thread::Builder::new()
            .name(format!("fc_vcpu{}", cpu_id))
            .spawn(move || {
                unsafe {
                    extern "C" fn handle_signal() {}
                    // Our signal handler does nothing and is trivially async signal safe.
                    register_signal_handler(0, handle_signal).expect(
                        "failed to register vcpu signal handler",
                    );
                }

                vcpu_thread_barrier.wait();

                loop {
                    match vcpu.run() {
                        Ok(run) => {
                            match run {
                                VcpuExit::IoIn(addr, data) => {
                                    io_bus.read(addr as u64, data);
                                }
                                VcpuExit::IoOut(addr, data) => {
                                    io_bus.write(addr as u64, data);
                                }
                                VcpuExit::MmioRead(_, _) => {}
                                VcpuExit::MmioWrite(_, _) => {}
                                VcpuExit::Hlt => {
                                    info!("KVM_EXIT_HLT");
                                    break;
                                }
                                VcpuExit::Shutdown => {
                                    info!("KVM_EXIT_SHUTDOWN");
                                    break;
                                }
                                r => {
                                    error!("unexpected exit reason: {:?}", r);
                                    break;
                                }
                            }
                        }
                        Err(e) => {
                            match e.errno() {
                                libc::EAGAIN | libc::EINTR => {}
                                _ => {
                                    error!("vcpu hit unknown error: {:?}", e);
                                    break;
                                }
                            }
                        }
                    }

                    if kill_signaled.load(Ordering::SeqCst) {
                        break;
                    }
                }

                vcpu_exit_evt.write(1).expect(
                    "failed to signal vcpu exit eventfd",
                );

            })
            .map_err(Error::VcpuSpawn)?);
    }

    vcpu_thread_barrier.wait();

    run_control(stdio_serial, exit_evt, kill_signaled, vcpu_handles)
}

fn run_control(
    stdio_serial: Arc<Mutex<devices::Serial>>,
    exit_evt: EventFd,
    kill_signaled: Arc<AtomicBool>,
    vcpu_handles: Vec<JoinHandle<()>>,
) -> Result<()> {
    const EXIT: u32 = 0;
    const STDIN: u32 = 1;

    let stdin_handle = io::stdin();
    let stdin_lock = stdin_handle.lock();
    stdin_lock.set_raw_mode().expect(
        "failed to set terminal raw mode",
    );

    let mut pollables = Vec::new();
    pollables.push((EXIT, &exit_evt as &Pollable));
    pollables.push((STDIN, &stdin_lock as &Pollable));

    let mut poller = Poller::new(pollables.len());

    'poll: loop {
        let tokens = match poller.poll(&pollables[..]) {
            Ok(v) => v,
            Err(e) => {
                error!("failed to poll: {:?}", e);
                break;
            }
        };

        for &token in tokens {
            match token {
                EXIT => {
                    info!("vcpu requested shutdown");
                    break 'poll;
                }
                STDIN => {
                    let mut out = [0u8; 64];
                    match stdin_lock.read_raw(&mut out[..]) {
                        Ok(0) => {
                            // Zero-length read indicates EOF. Remove from pollables.
                            pollables.retain(|&pollable| pollable.0 != STDIN);
                        }
                        Err(e) => {
                            warn!("error while reading stdin: {:?}", e);
                            pollables.retain(|&pollable| pollable.0 != STDIN);
                        }
                        Ok(count) => {
                            stdio_serial
                                .lock()
                                .unwrap()
                                .queue_input_bytes(&out[..count])
                                .expect("failed to queue bytes into serial port");
                        }
                    }
                }
                _ => {}
            }
        }
    }

    kill_signaled.store(true, Ordering::SeqCst);
    for handle in vcpu_handles {
        match handle.kill(0) {
            Ok(_) => {
                if let Err(e) = handle.join() {
                    error!("failed to join vcpu thread: {:?}", e);
                }
            }
            Err(e) => error!("failed to kill vcpu thread: {:?}", e),
        }
    }

    stdin_lock.set_canon_mode().expect(
        "failed to restore canonical mode for terminal",
    );

    Ok(())
}



pub fn run_x86_code() {
    // This example based on https://lwn.net/Articles/658511/
    let code = [
        /* mov $0x3f8, %dx */
        0xba,
        0xf8,
        0x03,
        /* add %bl, %al */
        0x00,
        0xd8,
        /* add $'0', %al */
        0x04,
        '0' as u8,
        /* out %al, (%dx) */
        0xee,
        /* mov $'\n', %al */
        0xb0,
        '\n' as u8,
        /* out %al, (%dx) */
        0xee,
        /* hlt */
        0xf4,
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
            }
            VcpuExit::Hlt => {
                io::stdout().write(b"KVM_EXIT_HLT\n").unwrap();
                break;
            }
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

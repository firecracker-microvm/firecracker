extern crate libc;
#[macro_use]
extern crate sys_util;
extern crate kvm_sys;
extern crate kvm;
extern crate kernel_loader;
extern crate x86_64;
extern crate clap;
extern crate devices;
extern crate epoll;
#[macro_use(defer)]
extern crate scopeguard;

pub mod machine;
mod vm_control;
mod vstate;

use std::ffi::CStr;
use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::io::{self, stdout};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use kvm::*;
use vstate::{Vm, Vcpu};
use sys_util::{register_signal_handler, EventFd, GuestAddress, GuestMemory, Killable, Terminal};
use machine::MachineCfg;
use scopeguard::guard;

const KERNEL_START_OFFSET: usize = 0x200000;
const CMDLINE_OFFSET: usize = 0x20000;

#[derive(Debug)]
pub enum Error {
    ConfigureSystem(x86_64::Error),
    EpollFd(std::io::Error),
    EventFd(sys_util::Error),
    GuestMemory(sys_util::GuestMemoryError),
    Kernel(std::io::Error),
    KernelLoader(kernel_loader::Error),
    Kvm(sys_util::Error),
    Poll(std::io::Error),
    Serial(sys_util::Error),
    Terminal(sys_util::Error),
    Vcpu(vstate::Error),
    VcpuConfigure(vstate::Error),
    VcpuSpawn(std::io::Error),
    Vm(vstate::Error),
    VmSetup(vstate::Error),
    VmIOBus(vstate::Error),
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
    let mem_size = cfg.mem_size << 20;
    let arch_mem_regions = x86_64::arch_memory_regions(mem_size);

    let mut kernel_file = File::open(&cfg.kernel_path).map_err(Error::Kernel)?;

    let cmdline: &CStr = &cfg.kernel_cmdline;
    let vcpu_count = cfg.vcpu_count;
    let kernel_start_addr = GuestAddress(KERNEL_START_OFFSET);
    let cmdline_addr = GuestAddress(CMDLINE_OFFSET);

    let guest_mem = GuestMemory::new(&arch_mem_regions).map_err(
        Error::GuestMemory,
    )?;

    let kvm = Kvm::new().map_err(Error::Kvm)?;
    let vm = Vm::new(&kvm, guest_mem).map_err(Error::Vm)?;

    vm.setup().map_err(Error::VmSetup)?;

    kernel_loader::load_kernel(vm.get_memory(), kernel_start_addr, &mut kernel_file)?;
    kernel_loader::load_cmdline(vm.get_memory(), cmdline_addr, cmdline)?;

    x86_64::configure_system(
        vm.get_memory(),
        kernel_start_addr,
        cmdline_addr,
        cmdline.to_bytes().len() + 1,
        vcpu_count,
    )?;

    let mut io_bus = devices::Bus::new();
    let exit_evt = EventFd::new().map_err(Error::EventFd)?;
    let com_evt_1_3 = EventFd::new().map_err(Error::EventFd)?;
    let com_evt_2_4 = EventFd::new().map_err(Error::EventFd)?;
    let stdio_serial = Arc::new(Mutex::new(devices::Serial::new_out(
        com_evt_1_3.try_clone().map_err(Error::EventFd)?,
        Box::new(stdout()),
    )));
    //TODO: put all thse things related to setting up io bus in a struct or something
    vm.set_io_bus(
        &mut io_bus,
        &stdio_serial,
        &com_evt_1_3,
        &com_evt_2_4,
        &exit_evt,
    ).map_err(Error::VmIOBus)?;

    let mut vcpu_handles = Vec::with_capacity(vcpu_count as usize);
    let vcpu_thread_barrier = Arc::new(Barrier::new((vcpu_count + 1) as usize));
    let kill_signaled = Arc::new(AtomicBool::new(false));

    for cpu_id in 0..vcpu_count {
        let io_bus = io_bus.clone();
        let kill_signaled = kill_signaled.clone();
        let vcpu_thread_barrier = vcpu_thread_barrier.clone();
        let vcpu_exit_evt = exit_evt.try_clone().map_err(Error::EventFd)?;

        let mut vcpu = Vcpu::new(cpu_id, &vm).map_err(Error::Vcpu)?;
        vcpu.configure(vcpu_count, kernel_start_addr, &vm).map_err(
            Error::VcpuConfigure,
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
                            match e {
                                vstate::Error::VcpuRun(ref v) => {
                                    match v.errno() {
                                        libc::EAGAIN | libc::EINTR => {}
                                        _ => {
                                            error!("vcpu hit unknown error: {:?}", e);
                                            break;
                                        }
                                    }
                                }
                                _ => {
                                    error!("unrecognized error type for vcpu run");
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

    let res = run_control(stdio_serial, exit_evt);

    kill_signaled.store(true, Ordering::SeqCst);
    for handle in vcpu_handles {
        match handle.kill(0) {
            Ok(_) => {
                if let Err(e) = handle.join() {
                    warn!("failed to join vcpu thread: {:?}", e);
                }
            }
            Err(e) => warn!("failed to kill vcpu thread: {:?}", e),
        }
    }

    res
}

fn run_control(stdio_serial: Arc<Mutex<devices::Serial>>, exit_evt: EventFd) -> Result<()> {
    const EXIT_TOKEN: u64 = 0;
    const STDIN_TOKEN: u64 = 1;
    const EPOLL_EVENTS_LEN: usize = 100;

    let epoll_raw_fd = epoll::create(true).map_err(Error::EpollFd)?;
    let epoll_raw_fd = guard(epoll_raw_fd, |epoll_raw_fd| {
        let rc = unsafe { libc::close(*epoll_raw_fd) };
        if rc != 0 {
            warn!("Cannot close epoll");
        }
    });

    epoll::ctl(
        *epoll_raw_fd,
        epoll::EPOLL_CTL_ADD,
        exit_evt.as_raw_fd(),
        epoll::Event::new(epoll::EPOLLIN, EXIT_TOKEN),
    ).map_err(Error::EpollFd)?;

    let stdin_handle = io::stdin();
    let stdin_lock = stdin_handle.lock();
    stdin_lock.set_raw_mode().map_err(Error::Terminal)?;
    defer! {{
        if let Err(e) = stdin_lock.set_canon_mode() {
            warn!("cannot set canon mode for stdin: {:?}", e);
        }
    }};

    epoll::ctl(
        *epoll_raw_fd,
        epoll::EPOLL_CTL_ADD,
        libc::STDIN_FILENO,
        epoll::Event::new(epoll::EPOLLIN, STDIN_TOKEN),
    ).map_err(Error::EpollFd)?;

    let mut events = Vec::<epoll::Event>::with_capacity(EPOLL_EVENTS_LEN);
    // Safe as we pass to set_len the value passed to with_capacity.
    unsafe { events.set_len(EPOLL_EVENTS_LEN) };

    'poll: loop {
        let num_events = epoll::wait(*epoll_raw_fd, -1, &mut events[..]).map_err(
            Error::Poll,
        )?;

        for i in 0..num_events {
            match events[i].data() {
                EXIT_TOKEN => {
                    info!("vcpu requested shutdown");
                    break 'poll;
                }
                STDIN_TOKEN => {
                    let mut out = [0u8; 64];
                    match stdin_lock.read_raw(&mut out[..]) {
                        Ok(0) => {
                            // Zero-length read indicates EOF. Remove from pollables.
                            epoll::ctl(
                                *epoll_raw_fd,
                                epoll::EPOLL_CTL_DEL,
                                libc::STDIN_FILENO,
                                events[i],
                            ).map_err(Error::EpollFd)?;
                        }
                        Err(e) => {
                            warn!("error while reading stdin: {:?}", e);
                            epoll::ctl(
                                *epoll_raw_fd,
                                epoll::EPOLL_CTL_DEL,
                                libc::STDIN_FILENO,
                                events[i],
                            ).map_err(Error::EpollFd)?;
                        }
                        Ok(count) => {
                            stdio_serial
                                .lock()
                                .unwrap()
                                .queue_input_bytes(&out[..count])
                                .map_err(Error::Serial)?;
                        }
                    }
                }
                _ => {}
            }
        }
    }

    Ok(())
}

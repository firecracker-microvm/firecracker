extern crate epoll;
extern crate libc;
#[macro_use(defer)]
extern crate scopeguard;

extern crate devices;
extern crate kernel_loader;
extern crate kvm;
extern crate kvm_sys;
#[macro_use]
extern crate sys_util;
extern crate x86_64;

pub mod device_manager;
pub mod kernel_cmdline;
pub mod machine;
mod vm_control;
mod vstate;

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{self, stdout};
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use device_manager::*;
use devices::virtio;
use devices::{DeviceEventT, EpollHandler};
use kvm::*;
use machine::MachineCfg;
use sys_util::{register_signal_handler, EventFd, GuestAddress, GuestMemory, Killable, Terminal};
use vm_control::VmResponse;
use vstate::{Vcpu, Vm};

const KERNEL_START_OFFSET: usize = 0x200000;
const CMDLINE_OFFSET: usize = 0x20000;
const CMDLINE_MAX_SIZE: usize = KERNEL_START_OFFSET - CMDLINE_OFFSET;

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
    RootDiskImage(std::io::Error),
    RootBlockDeviceNew(sys_util::Error),
    RegisterBlock(device_manager::Error),
    NetDeviceNew(devices::virtio::NetError),
    RegisterNet(device_manager::Error),
    DeviceVmRequest(sys_util::Error),
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

#[derive(Clone, Copy)]
enum EpollDispatch {
    Exit,
    Stdin,
    DeviceHandler(usize, DeviceEventT),
}

struct MaybeHandler {
    handler: Option<Box<EpollHandler>>,
    receiver: Receiver<Box<EpollHandler>>,
}

impl MaybeHandler {
    fn new(receiver: Receiver<Box<EpollHandler>>) -> Self {
        MaybeHandler {
            handler: None,
            receiver,
        }
    }
}

//This should handle epoll related business from now on. A glaring shortcoming of the current
//design is the liberal passing around of raw_fds, and duping of file descriptors. This issue
//will be solved when we also implement device removal.
struct EpollContext {
    epoll_raw_fd: RawFd,
    dispatch_table: Vec<EpollDispatch>,
    device_handlers: Vec<MaybeHandler>,
}

impl EpollContext {
    pub fn new(exit_evt_raw_fd: RawFd) -> Result<Self> {
        let epoll_raw_fd = epoll::create(true).map_err(Error::EpollFd)?;

        //some reasonable initial capacity values
        let mut dispatch_table = Vec::with_capacity(20);
        let device_handlers = Vec::with_capacity(6);

        epoll::ctl(
            epoll_raw_fd,
            epoll::EPOLL_CTL_ADD,
            exit_evt_raw_fd,
            epoll::Event::new(epoll::EPOLLIN, dispatch_table.len() as u64),
        ).map_err(Error::EpollFd)?;

        dispatch_table.push(EpollDispatch::Exit);

        epoll::ctl(
            epoll_raw_fd,
            epoll::EPOLL_CTL_ADD,
            libc::STDIN_FILENO,
            epoll::Event::new(epoll::EPOLLIN, dispatch_table.len() as u64),
        ).map_err(Error::EpollFd)?;

        dispatch_table.push(EpollDispatch::Stdin);

        Ok(EpollContext {
            epoll_raw_fd,
            dispatch_table,
            device_handlers,
        })
    }

    fn allocate_tokens(&mut self, count: usize) -> (u64, Sender<Box<EpollHandler>>) {
        let dispatch_base = self.dispatch_table.len() as u64;
        let device_idx = self.device_handlers.len();
        let (sender, receiver) = channel();

        for x in 0..count - 1 {
            self.dispatch_table
                .push(EpollDispatch::DeviceHandler(device_idx, x as DeviceEventT));
        }

        self.device_handlers.push(MaybeHandler::new(receiver));

        (dispatch_base, sender)
    }

    pub fn allocate_virtio_block_tokens(&mut self) -> virtio::block::EpollConfig {
        let (dispatch_base, sender) = self.allocate_tokens(2);
        virtio::block::EpollConfig::new(dispatch_base, self.epoll_raw_fd, sender)
    }

    pub fn allocate_virtio_net_tokens(&mut self) -> virtio::net::EpollConfig {
        let (dispatch_base, sender) = self.allocate_tokens(4);
        virtio::net::EpollConfig::new(dispatch_base, self.epoll_raw_fd, sender)
    }

    fn get_device_handler(&mut self, device_idx: usize) -> &mut EpollHandler {
        let ref mut maybe = self.device_handlers[device_idx];
        match maybe.handler {
            Some(ref mut v) => v.as_mut(),
            None => {
                //this should only be called in response to an epoll trigger, and the channel
                //should always contain a message after the events were added to epoll
                //by the activate() call
                maybe
                    .handler
                    .get_or_insert(maybe.receiver.try_recv().unwrap())
                    .as_mut()
            }
        }
    }
}

impl Drop for EpollContext {
    fn drop(&mut self) {
        let rc = unsafe { libc::close(self.epoll_raw_fd) };
        if rc != 0 {
            warn!("Cannot close epoll");
        }
    }
}

pub fn boot_kernel(cfg: MachineCfg, kill_on_exit: bool) -> Result<()> {
    let mem_size = cfg.mem_size << 20;
    let arch_mem_regions = x86_64::arch_memory_regions(mem_size);

    //we're using unwrap here because the kernel_path is mandatory for now
    let mut kernel_file = File::open(cfg.kernel_path.as_ref().unwrap()).map_err(Error::Kernel)?;

    let mut cmdline = kernel_cmdline::Cmdline::new(CMDLINE_MAX_SIZE);
    cmdline
        .insert_str(&cfg.kernel_cmdline)
        .expect("could not use the specified kernel cmdline");

    let vcpu_count = cfg.vcpu_count;
    let kernel_start_addr = GuestAddress(KERNEL_START_OFFSET);
    let cmdline_addr = GuestAddress(CMDLINE_OFFSET);

    let guest_mem = GuestMemory::new(&arch_mem_regions).map_err(Error::GuestMemory)?;

    let exit_evt = EventFd::new().map_err(Error::EventFd)?;

    let mut epoll_context = EpollContext::new(exit_evt.as_raw_fd())?;

    //adding VIRTIO mmio devices

    //todo why irq_base 5 and not some other value?
    /*
    as for the other parameters:
    - mmio_len has to be larger than 0x100 (the offset where the configuration space starts from
    the beginning of the memory mapped device registers) + the size of the configuration space.
    I guess 0x1000 is a nice, round value. Also, crosvm literally supplies 4K as the first param
    of the virtio_mmio.device kernel cmdline option, so this has to match.
    - mmio_base, as far as I can tell, is just some address which is not seen as regular memory
    by the kernel. In this case, it seems 0xd0000000 is right at the beginning of the memory gap
    created by x86_64::arch_memory_regions(mem_size). With the virtio_mmio.device option,
    the kernel is informed about the start of the mapping for each device.
    */
    let mut device_manager = DeviceManager::new(guest_mem.clone(), 0x1000, 0xd0000000, 5);

    if let Some(root_blk_file) = cfg.root_blk_file.as_ref() {
        //fixme this is a super simple solution; improve at some point
        //the root option has some more parameters IIRC; are any of them needed/useful?
        cmdline.insert_str(" root=/dev/vda").unwrap();

        //adding root blk device from file (currently always opened as read + write)
        let root_image = OpenOptions::new()
            .read(true)
            .write(true)
            .open(root_blk_file)
            .map_err(Error::RootDiskImage)?;

        let epoll_config = epoll_context.allocate_virtio_block_tokens();

        let block_box = Box::new(devices::virtio::Block::new(root_image, epoll_config)
            .map_err(Error::RootBlockDeviceNew)?);

        device_manager
            .register_mmio(block_box, &mut cmdline)
            .map_err(Error::RegisterBlock)?;
    }

    if cfg.host_ip.is_some() {
        let epoll_config = epoll_context.allocate_virtio_net_tokens();

        let net_box = Box::new(devices::virtio::Net::new(
            cfg.host_ip.unwrap(),
            cfg.subnet_mask,
            epoll_config,
        ).map_err(Error::NetDeviceNew)?);

        device_manager
            .register_mmio(net_box, &mut cmdline)
            .map_err(Error::RegisterNet)?;
    }

    let kvm = Kvm::new().map_err(Error::Kvm)?;
    let vm = Vm::new(&kvm, guest_mem).map_err(Error::Vm)?;

    vm.setup().map_err(Error::VmSetup)?;

    for request in device_manager.vm_requests {
        if let VmResponse::Err(e) = request.execute(vm.get_fd()) {
            return Err(Error::DeviceVmRequest(e));
        }
    }

    let cmdline_cstr = CString::new(cmdline).unwrap();

    kernel_loader::load_kernel(vm.get_memory(), kernel_start_addr, &mut kernel_file)?;
    kernel_loader::load_cmdline(vm.get_memory(), cmdline_addr, &cmdline_cstr)?;

    x86_64::configure_system(
        vm.get_memory(),
        kernel_start_addr,
        cmdline_addr,
        cmdline_cstr.to_bytes().len() + 1,
        vcpu_count,
    )?;

    let mut io_bus = devices::Bus::new();
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
        let mmio_bus = device_manager.bus.clone();
        let kill_signaled = kill_signaled.clone();
        let vcpu_thread_barrier = vcpu_thread_barrier.clone();
        let vcpu_exit_evt = exit_evt.try_clone().map_err(Error::EventFd)?;

        let mut vcpu = Vcpu::new(cpu_id, &vm).map_err(Error::Vcpu)?;
        vcpu.configure(vcpu_count, kernel_start_addr, &vm)
            .map_err(Error::VcpuConfigure)?;
        vcpu_handles.push(thread::Builder::new()
            .name(format!("fc_vcpu{}", cpu_id))
            .spawn(move || {
                unsafe {
                    extern "C" fn handle_signal() {}
                    // Our signal handler does nothing and is trivially async signal safe.
                    register_signal_handler(0, handle_signal)
                        .expect("failed to register vcpu signal handler");
                }

                vcpu_thread_barrier.wait();

                loop {
                    match vcpu.run() {
                        Ok(run) => match run {
                            VcpuExit::IoIn(addr, data) => {
                                io_bus.read(addr as u64, data);
                            }
                            VcpuExit::IoOut(addr, data) => {
                                io_bus.write(addr as u64, data);
                            }
                            VcpuExit::MmioRead(addr, data) => {
                                mmio_bus.read(addr, data);
                            }
                            VcpuExit::MmioWrite(addr, data) => {
                                mmio_bus.write(addr, data);
                            }
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
                        },
                        Err(e) => match e {
                            vstate::Error::VcpuRun(ref v) => match v.errno() {
                                libc::EAGAIN | libc::EINTR => {}
                                _ => {
                                    error!("vcpu hit unknown error: {:?}", e);
                                    break;
                                }
                            },
                            _ => {
                                error!("unrecognized error type for vcpu run");
                                break;
                            }
                        },
                    }

                    if kill_signaled.load(Ordering::SeqCst) {
                        break;
                    }
                }

                vcpu_exit_evt
                    .write(1)
                    .expect("failed to signal vcpu exit eventfd");
            })
            .map_err(Error::VcpuSpawn)?);
    }

    vcpu_thread_barrier.wait();

    let res = run_control(stdio_serial, epoll_context);

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

    if kill_on_exit {
        std::process::exit(0);
    }

    res
}

fn run_control(
    stdio_serial: Arc<Mutex<devices::Serial>>,
    mut epoll_context: EpollContext,
) -> Result<()> {
    let stdin_handle = io::stdin();
    let stdin_lock = stdin_handle.lock();
    stdin_lock.set_raw_mode().map_err(Error::Terminal)?;
    defer! {{
        if let Err(e) = stdin_lock.set_canon_mode() {
            warn!("cannot set canon mode for stdin: {:?}", e);
        }
    }};

    const EPOLL_EVENTS_LEN: usize = 100;

    let mut events = Vec::<epoll::Event>::with_capacity(EPOLL_EVENTS_LEN);
    // Safe as we pass to set_len the value passed to with_capacity.
    unsafe { events.set_len(EPOLL_EVENTS_LEN) };

    let epoll_raw_fd = epoll_context.epoll_raw_fd;

    'poll: loop {
        let num_events = epoll::wait(epoll_raw_fd, -1, &mut events[..]).map_err(Error::Poll)?;

        for i in 0..num_events {
            let dispatch_idx = events[i].data() as usize;
            let dispatch_type = epoll_context.dispatch_table[dispatch_idx];

            match dispatch_type {
                EpollDispatch::Exit => {
                    info!("vcpu requested shutdown");
                    break 'poll;
                }
                EpollDispatch::Stdin => {
                    let mut out = [0u8; 64];
                    match stdin_lock.read_raw(&mut out[..]) {
                        Ok(0) => {
                            // Zero-length read indicates EOF. Remove from pollables.
                            epoll::ctl(
                                epoll_raw_fd,
                                epoll::EPOLL_CTL_DEL,
                                libc::STDIN_FILENO,
                                events[i],
                            ).map_err(Error::EpollFd)?;
                        }
                        Err(e) => {
                            warn!("error while reading stdin: {:?}", e);
                            epoll::ctl(
                                epoll_raw_fd,
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
                EpollDispatch::DeviceHandler(device_idx, device_token) => {
                    let handler = epoll_context.get_device_handler(device_idx);
                    handler.handle_event(device_token, events[i].events().bits());
                }
            }
        }
    }

    Ok(())
}

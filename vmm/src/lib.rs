extern crate epoll;
extern crate libc;
#[macro_use(defer)]
extern crate scopeguard;

extern crate api_server;
extern crate devices;
extern crate kernel_loader;
extern crate kvm;
extern crate kvm_sys;
#[macro_use]
extern crate sys_util;
extern crate x86_64;

pub mod device_config;
pub mod device_manager;
pub mod kernel_cmdline;
pub mod machine;
mod vm_control;
mod vstate;

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{self, stdout};
use std::os::unix::io::{AsRawFd, RawFd};
use std::result;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use api_server::ApiRequest;
use api_server::request::async::{AsyncOutcome, AsyncRequest};
use api_server::request::sync::{DriveError, PutDriveOutcome, SyncRequest};
use device_config::*;
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
    KernelCmdLine(kernel_cmdline::Error),
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
    CreateVirtioVsock(devices::virtio::vhost::Error),
    RegisterMMIOVsockDevice(device_manager::Error),
    DeviceVmRequest(sys_util::Error),
    DriveError(DriveError),
    ApiChannel,
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

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EpollDispatch {
    Exit,
    Stdin,
    DeviceHandler(usize, DeviceEventT),
    ApiRequest,
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

pub struct EpollEvent {
    dispatch_index: u64,
    event_fd: EventFd,
}

//This should handle epoll related business from now on. A glaring shortcoming of the current
//design is the liberal passing around of raw_fds, and duping of file descriptors. This issue
//will be solved when we also implement device removal.
pub struct EpollContext {
    epoll_raw_fd: RawFd,
    stdin_index: u64,
    // FIXME: find a different design as this does not scale. This Vec can only grow.
    dispatch_table: Vec<Option<EpollDispatch>>,
    device_handlers: Vec<MaybeHandler>,
}

impl EpollContext {
    pub fn new() -> Result<Self> {
        let epoll_raw_fd = epoll::create(true).map_err(Error::EpollFd)?;

        let mut dispatch_table = Vec::with_capacity(20);
        let stdin_index = dispatch_table.len() as u64;
        dispatch_table.push(None);
        Ok(EpollContext {
            epoll_raw_fd,
            stdin_index,
            dispatch_table,
            device_handlers: Vec::with_capacity(6),
        })
    }

    pub fn enable_stdin_event(&mut self) -> Result<()> {
        epoll::ctl(
            self.epoll_raw_fd,
            epoll::EPOLL_CTL_ADD,
            libc::STDIN_FILENO,
            epoll::Event::new(epoll::EPOLLIN, self.stdin_index),
        ).map_err(Error::EpollFd)?;
        self.dispatch_table[self.stdin_index as usize] = Some(EpollDispatch::Stdin);

        Ok(())
    }

    pub fn disable_stdin_event(&mut self) -> Result<()> {
        epoll::ctl(
            self.epoll_raw_fd,
            epoll::EPOLL_CTL_DEL,
            libc::STDIN_FILENO,
            epoll::Event::new(epoll::EPOLLIN, self.stdin_index),
        ).map_err(Error::EpollFd)?;
        self.dispatch_table[self.stdin_index as usize] = None;

        Ok(())
    }

    pub fn add_event(&mut self, evfd: EventFd, token: EpollDispatch) -> Result<EpollEvent> {
        let index = self.dispatch_table.len() as u64;
        epoll::ctl(
            self.epoll_raw_fd,
            epoll::EPOLL_CTL_ADD,
            evfd.as_raw_fd(),
            epoll::Event::new(epoll::EPOLLIN, index),
        ).map_err(Error::EpollFd)?;
        self.dispatch_table.push(Some(token));

        Ok(EpollEvent {
            dispatch_index: index,
            event_fd: evfd,
        })
    }

    pub fn remove_event(&mut self, epoll_event: EpollEvent) -> Result<()> {
        epoll::ctl(
            self.epoll_raw_fd,
            epoll::EPOLL_CTL_DEL,
            epoll_event.event_fd.as_raw_fd(),
            epoll::Event::new(epoll::EPOLLIN, epoll_event.dispatch_index),
        ).map_err(Error::EpollFd)?;
        self.dispatch_table[epoll_event.dispatch_index as usize] = None;

        Ok(())
    }

    fn allocate_tokens(&mut self, count: usize) -> (u64, Sender<Box<EpollHandler>>) {
        let dispatch_base = self.dispatch_table.len() as u64;
        let device_idx = self.device_handlers.len();
        let (sender, receiver) = channel();

        for x in 0..count - 1 {
            self.dispatch_table.push(Some(EpollDispatch::DeviceHandler(
                device_idx,
                x as DeviceEventT,
            )));
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

    pub fn allocate_virtio_vsock_tokens(&mut self) -> virtio::vhost::handle::VhostEpollConfig {
        let (dispatch_base, sender) = self.allocate_tokens(2);
        virtio::vhost::handle::VhostEpollConfig::new(dispatch_base, self.epoll_raw_fd, sender)
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

pub struct KernelConfig {
    cmdline: kernel_cmdline::Cmdline,
    // TODO: this structure should also contain the kernel_path, kernel_start addr and others
}

pub struct Vmm {
    cfg: MachineCfg,

    /// guest VM core resources
    kernel_config: KernelConfig,
    kill_signaled: Option<Arc<AtomicBool>>,
    vcpu_handles: Option<Vec<thread::JoinHandle<()>>>,
    exit_evt: Option<EpollEvent>,
    stdio_serial: Option<Arc<Mutex<devices::Serial>>>,
    vm: Option<Vm>,

    /// guest VM devices
    // If there is a Root Block Device, this should be added as the first element of the list
    // This is necessary because we want the root to always be mounted on /dev/vda
    block_device_configs: BlockDeviceConfigs,

    epoll_context: EpollContext,

    /// api resources
    api_event: EpollEvent,
    from_api: Receiver<Box<ApiRequest>>,
}

impl Vmm {
    pub fn new(
        cfg: MachineCfg,
        api_event_fd: EventFd,
        from_api: Receiver<Box<ApiRequest>>,
    ) -> Result<Self> {
        let mut epoll_context = EpollContext::new()?;
        // if this fails, it's fatal, .expect() it
        let api_event = epoll_context
            .add_event(api_event_fd, EpollDispatch::ApiRequest)
            .expect("cannot add API eventfd to epoll");
        let cmdline = kernel_cmdline::Cmdline::new(CMDLINE_MAX_SIZE);
        let kernel_config = KernelConfig { cmdline };
        let block_device_configs = BlockDeviceConfigs::new();
        Ok(Vmm {
            cfg,
            kernel_config,
            kill_signaled: None,
            vcpu_handles: None,
            exit_evt: None,
            stdio_serial: None,
            vm: None,
            block_device_configs,
            epoll_context,
            api_event,
            from_api,
        })
    }

    /// only call this function as part of the API
    /// If the drive_id does not exit, a new Block Device Config is added to the list.
    /// Else, the drive will be updated
    pub fn put_block_device(
        &mut self,
        block_device_config: BlockDeviceConfig,
    ) -> result::Result<(), DriveError> {
        // if the id of the drive already exists in the list, the operation is update
        if self.block_device_configs
            .contains_drive_id(block_device_config.drive_id.clone())
        {
            return Err(DriveError::NotImplemented);
        } else {
            self.block_device_configs.add(block_device_config)
        }
    }

    /// Attach all block devices from the BlockDevicesConfig
    /// If there is no root block device, no other devices are attached.The root device should be
    /// the first to be attached as a way to make sure it ends up on /dev/vda
    /// This function is to be called only from boot_source
    fn attach_block_devices(&mut self, device_manager: &mut DeviceManager) -> Result<()> {
        // If there's no root device, do not attach any other devices
        let block_dev = &self.block_device_configs;
        if block_dev.has_root_block_device() {
            // this is a simple solution to add a block as a root device; should be improved
            self.kernel_config
                .cmdline
                .insert_str(" root=/dev/vda")
                .map_err(|e| Error::RegisterBlock(device_manager::Error::Cmdline(e)))?;

            let epoll_context = &mut self.epoll_context;
            let kernel_cmdline = &mut self.kernel_config.cmdline;
            for drive_config in self.block_device_configs.config_list.iter() {
                // adding root blk device from file (currently always opened as read + write)
                let root_image = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&drive_config.path_on_host)
                    .map_err(Error::RootDiskImage)?;
                let epoll_config = epoll_context.allocate_virtio_block_tokens();

                let block_box = Box::new(devices::virtio::Block::new(root_image, epoll_config)
                    .map_err(Error::RootBlockDeviceNew)?);

                device_manager
                    .register_mmio(block_box, kernel_cmdline)
                    .map_err(Error::RegisterBlock)?;
            }
        }

        Ok(())
    }

    /// only call this from run_vmm() or other functions
    /// that can guarantee single instances
    pub fn boot_kernel(&mut self) -> Result<()> {
        let boot_result = {
            let mut try_boot = || -> Result<()> {
                let mem_size = self.cfg.mem_size << 20;
                let arch_mem_regions = x86_64::arch_memory_regions(mem_size);
                let guest_mem = GuestMemory::new(&arch_mem_regions).map_err(Error::GuestMemory)?;

                let vcpu_count = self.cfg.vcpu_count;

                let kernel_start_addr = GuestAddress(KERNEL_START_OFFSET);
                let cmdline_addr = GuestAddress(CMDLINE_OFFSET);
                self.kernel_config
                    .cmdline
                    .insert_str(&self.cfg.kernel_cmdline)
                    .map_err(Error::KernelCmdLine)?;

                /* Instantiating MMIO device manager
                'mmio_base' address has to be an address which is protected by the kernel, in this case
                the start of the x86 specific gap of memory (currently hardcoded at 768MiB)
                */
                let mut device_manager =
                    DeviceManager::new(guest_mem.clone(), x86_64::get_32bit_gap_start() as u64);

                self.attach_block_devices(&mut device_manager)?;

                // network device
                if self.cfg.host_ip.is_some() {
                    let epoll_config = self.epoll_context.allocate_virtio_net_tokens();

                    let net_box = Box::new(devices::virtio::Net::new(
                        // safe to unwrap since it's checked above
                        self.cfg.host_ip.unwrap(),
                        self.cfg.subnet_mask,
                        epoll_config,
                    ).map_err(Error::NetDeviceNew)?);

                    device_manager
                        .register_mmio(net_box, &mut self.kernel_config.cmdline)
                        .map_err(Error::RegisterNet)?;
                }

                if let Some(cid) = self.cfg.vsock_guest_cid {
                    let epoll_config = self.epoll_context.allocate_virtio_vsock_tokens();

                    let vsock_box = Box::new(devices::virtio::Vsock::new(cid, &guest_mem, epoll_config)
                        .map_err(Error::CreateVirtioVsock)?);
                    device_manager
                        .register_mmio(vsock_box, &mut self.kernel_config.cmdline)
                        .map_err(Error::RegisterMMIOVsockDevice)?;
                }

                let kvm = Kvm::new().map_err(Error::Kvm)?;
                self.vm = Some(Vm::new(&kvm, guest_mem).map_err(Error::Vm)?);
                // safe to unwrap since it's set just above
                let vm = self.vm.as_mut().unwrap();

                vm.setup().map_err(Error::VmSetup)?;

                for request in device_manager.vm_requests {
                    if let VmResponse::Err(e) = request.execute(vm.get_fd()) {
                        return Err(Error::DeviceVmRequest(e));
                    }
                }

                // This is the easy way out of consuming the value of the kernel_cmdline.
                // TODO: refactor the kernel_cmdline struct in order to have a CString instead of a String.
                let cmdline_cstring = CString::new(self.kernel_config.cmdline.clone())
                    .map_err(|_| Error::KernelCmdLine(kernel_cmdline::Error::InvalidAscii))?;

                // we're using unwrap here because the kernel_path is mandatory for now
                let mut kernel_file =
                    File::open(self.cfg.kernel_path.as_ref().unwrap()).map_err(Error::Kernel)?;
                kernel_loader::load_kernel(vm.get_memory(), kernel_start_addr, &mut kernel_file)?;
                kernel_loader::load_cmdline(vm.get_memory(), cmdline_addr, &cmdline_cstring)?;

                x86_64::configure_system(
                    vm.get_memory(),
                    kernel_start_addr,
                    cmdline_addr,
                    cmdline_cstring.to_bytes().len() + 1,
                    vcpu_count,
                )?;

                let event_fd = EventFd::new().map_err(Error::EventFd)?;
                let exit_epoll_evt = self.epoll_context.add_event(event_fd, EpollDispatch::Exit)?;
                self.exit_evt = Some(exit_epoll_evt);
                // safe to unwrap since it's set just above
                let exit_evt = &self.exit_evt.as_mut().unwrap().event_fd;

                let mut io_bus = devices::Bus::new();
                let com_evt_1_3 = EventFd::new().map_err(Error::EventFd)?;
                let com_evt_2_4 = EventFd::new().map_err(Error::EventFd)?;
                self.stdio_serial = Some(Arc::new(Mutex::new(devices::Serial::new_out(
                    com_evt_1_3.try_clone().map_err(Error::EventFd)?,
                    Box::new(stdout()),
                ))));
                // safe to unwrap since it's set just above
                let stdio_serial = self.stdio_serial.as_mut().unwrap();

                self.epoll_context.enable_stdin_event()?;

                //TODO: put all thse things related to setting up io bus in a struct or something
                vm.set_io_bus(
                    &mut io_bus,
                    stdio_serial,
                    &com_evt_1_3,
                    &com_evt_2_4,
                    exit_evt,
                ).map_err(Error::VmIOBus)?;

                self.vcpu_handles = Some(Vec::with_capacity(vcpu_count as usize));
                // safe to unwrap since it's set just above
                let vcpu_handles = self.vcpu_handles.as_mut().unwrap();
                self.kill_signaled = Some(Arc::new(AtomicBool::new(false)));
                // safe to unwrap since it's set just above
                let kill_signaled = self.kill_signaled.as_mut().unwrap();

                let vcpu_thread_barrier = Arc::new(Barrier::new((vcpu_count + 1) as usize));

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

                            // TODO: find a way to report vCPU errors to the user,
                            // for now ignoring this result as there's nothing we can do
                            // for the failure case.
                            let _ = vcpu_exit_evt.write(1);
                        })
                        .map_err(Error::VcpuSpawn)?);
                }

                vcpu_thread_barrier.wait();

                Ok(())
            };

            try_boot()
        };

        if boot_result.is_err() {
            error!("boot failed: {:?}", boot_result);
            let _ = self.stop();
        }
        boot_result
    }

    fn stop(&mut self) -> Result<()> {
        if let Some(v) = self.kill_signaled.take() {
            v.store(true, Ordering::SeqCst);
        };

        if let Some(handles) = self.vcpu_handles.take() {
            for handle in handles {
                match handle.kill(0) {
                    Ok(_) => {
                        if let Err(e) = handle.join() {
                            warn!("failed to join vcpu thread: {:?}", e);
                        }
                    }
                    Err(e) => warn!("failed to kill vcpu thread: {:?}", e),
                }
            }
        };

        if let Some(evt) = self.exit_evt.take() {
            self.epoll_context.remove_event(evt)?;
        }
        self.epoll_context.disable_stdin_event()?;

        self.stdio_serial.take();
        self.vm.take();

        //TODO:
        // - clean epoll_context:
        //   - remove block, net
        Ok(())
    }

    pub fn run_control(&mut self) -> Result<()> {
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

        let epoll_raw_fd = self.epoll_context.epoll_raw_fd;

        'poll: loop {
            let num_events = epoll::wait(epoll_raw_fd, -1, &mut events[..]).map_err(Error::Poll)?;

            for i in 0..num_events {
                let dispatch_idx = events[i].data() as usize;

                if let Some(dispatch_type) = self.epoll_context.dispatch_table[dispatch_idx] {
                    match dispatch_type {
                        EpollDispatch::Exit => {
                            info!("vcpu requested shutdown");
                            match self.exit_evt {
                                Some(ref ev) => {
                                    ev.event_fd.read().map_err(Error::EventFd)?;
                                }
                                None => warn!("leftover exit-evt in epollcontext!"),
                            }
                            self.stop()?;
                            break 'poll;
                        }
                        EpollDispatch::Stdin => {
                            let mut out = [0u8; 64];
                            match stdin_lock.read_raw(&mut out[..]) {
                                Ok(0) => {
                                    // Zero-length read indicates EOF. Remove from pollables.
                                    self.epoll_context.disable_stdin_event()?;
                                }
                                Err(e) => {
                                    warn!("error while reading stdin: {:?}", e);
                                    self.epoll_context.disable_stdin_event()?;
                                }
                                Ok(count) => match self.stdio_serial {
                                    Some(ref mut serial) => {
                                        // unwrap() to panic if another thread panicked
                                        // while holding the lock
                                        serial
                                            .lock()
                                            .unwrap()
                                            .queue_input_bytes(&out[..count])
                                            .map_err(Error::Serial)?;
                                    }
                                    None => warn!("leftover stdin event in epollcontext!"),
                                },
                            }
                        }
                        EpollDispatch::DeviceHandler(device_idx, device_token) => {
                            let handler = self.epoll_context.get_device_handler(device_idx);
                            handler.handle_event(device_token, events[i].events().bits());
                        }
                        EpollDispatch::ApiRequest => {
                            self.api_event.event_fd.read().map_err(Error::EventFd)?;
                            self.run_api_cmd().unwrap_or_else(|_| {
                                warn!("got spurious notification from api thread");
                                ()
                            });
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn run_api_cmd(&mut self) -> Result<()> {
        let request = match self.from_api.try_recv() {
            Ok(t) => t,
            Err(TryRecvError::Empty) => {
                return Err(Error::ApiChannel);
            }
            Err(TryRecvError::Disconnected) => {
                panic!();
            }
        };
        match *request {
            ApiRequest::Async(req) => {
                match req {
                    AsyncRequest::StartInstance(sender) => {
                        let result = match self.boot_kernel() {
                            Ok(_) => AsyncOutcome::Ok(0),
                            Err(e) => AsyncOutcome::Error(format!("cannot boot kernel: {:?}", e)),
                        };
                        // doing expect() to crash this thread as well if the other thread crashed
                        sender.send(result).expect("one-shot channel closed");
                    }
                    AsyncRequest::StopInstance(sender) => {
                        let result = match self.stop() {
                            Ok(_) => AsyncOutcome::Ok(0),
                            Err(e) => AsyncOutcome::Error(format!(
                                "failed to stop instance! err: {:?}",
                                e
                            )),
                        };
                        // doing expect() to crash this thread as well if the other thread crashed
                        sender.send(result).expect("one-shot channel closed");
                    }
                };
            }
            ApiRequest::Sync(req) => {
                match req {
                    SyncRequest::PutDrive(drive_description, sender) => {
                        match self.put_block_device(BlockDeviceConfig::from(drive_description)) {
                            Ok(_) =>
                                // doing expect() to crash this thread if the other thread crashed
                                sender.send(Box::new(PutDriveOutcome::Created))
                                .map_err(|_| ())
                                .expect("one-shot channel closed"),
                            Err(e) =>
                                // doing expect() to crash this thread if the other thread crashed
                                sender.send(Box::new(e))
                                .map_err(|_| ())
                                .expect("one-shot channel closed"),
                        }
                    }
                };
            }
        };

        Ok(())
    }
}

pub fn start_vmm_thread(
    cfg: MachineCfg,
    api_event_fd: EventFd,
    from_api: Receiver<Box<ApiRequest>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        // if this fails, consider it fatal: .expect()
        let mut vmm = Vmm::new(cfg, api_event_fd, from_api).expect("cannot create VMM");
        // vmm thread errors are irrecoverable for now: .expect()
        vmm.run_control().expect("VMM thread fail");
        // TODO: maybe offer through API: an instance status reporting error messages (r)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_epoll_context_test() {
        assert!(EpollContext::new().is_ok());
    }

    #[test]
    fn enable_disable_stdin_test() {
        let mut ep = EpollContext::new().unwrap();
        // enabling stdin should work
        assert!(ep.enable_stdin_event().is_ok());
        // doing it again should fail
        assert!(ep.enable_stdin_event().is_err());

        // disabling stdin should work
        assert!(ep.disable_stdin_event().is_ok());
        // doing it again should fail
        assert!(ep.disable_stdin_event().is_err());

        // enabling stdin should work now
        assert!(ep.enable_stdin_event().is_ok());
        // disabling it again should work
        assert!(ep.disable_stdin_event().is_ok());
    }

    #[test]
    fn add_remove_event_test() {
        let mut ep = EpollContext::new().unwrap();
        let evfd = EventFd::new().unwrap();

        // adding new event should work
        let epev = ep.add_event(evfd, EpollDispatch::Exit);
        assert!(epev.is_ok());

        // removing event should work
        assert!(ep.remove_event(epev.unwrap()).is_ok());
    }

    #[test]
    fn epoll_event_test() {
        let mut ep = EpollContext::new().unwrap();
        let evfd = EventFd::new().unwrap();

        // adding new event should work
        let epev = ep.add_event(evfd, EpollDispatch::Exit);
        assert!(epev.is_ok());
        let epev = epev.unwrap();

        let evpoll_events_len = 10;
        let mut events = Vec::<epoll::Event>::with_capacity(evpoll_events_len);
        // Safe as we pass to set_len the value passed to with_capacity.
        unsafe { events.set_len(evpoll_events_len) };

        // epoll should have no pending events
        let epollret = epoll::wait(ep.epoll_raw_fd, 0, &mut events[..]);
        let num_events = epollret.unwrap();
        assert_eq!(num_events, 0);

        // raise the event
        assert!(epev.event_fd.write(1).is_ok());

        // epoll should report one event
        let epollret = epoll::wait(ep.epoll_raw_fd, 0, &mut events[..]);
        let num_events = epollret.unwrap();
        assert_eq!(num_events, 1);

        // reported event should be the one we raised
        let idx = events[0].data() as usize;
        assert!(ep.dispatch_table[idx].is_some());
        assert_eq!(*ep.dispatch_table[idx].as_ref().unwrap(), EpollDispatch::Exit);

        // removing event should work
        assert!(ep.remove_event(epev).is_ok());
    }

    #[test]
    fn epoll_event_try_get_after_remove_test() {
        let mut ep = EpollContext::new().unwrap();
        let evfd = EventFd::new().unwrap();

        // adding new event should work
        let epev = ep.add_event(evfd, EpollDispatch::Exit).unwrap();

        let evpoll_events_len = 10;
        let mut events = Vec::<epoll::Event>::with_capacity(evpoll_events_len);
        // Safe as we pass to set_len the value passed to with_capacity.
        unsafe { events.set_len(evpoll_events_len) };

        // raise the event
        assert!(epev.event_fd.write(1).is_ok());

        // removing event should work
        assert!(ep.remove_event(epev).is_ok());

        // epoll should have no pending events
        let epollret = epoll::wait(ep.epoll_raw_fd, 0, &mut events[..]);
        let num_events = epollret.unwrap();
        assert_eq!(num_events, 0);
    }

    #[test]
    fn epoll_event_try_use_after_remove_test() {
        let mut ep = EpollContext::new().unwrap();
        let evfd = EventFd::new().unwrap();

        // adding new event should work
        let epev = ep.add_event(evfd, EpollDispatch::Exit).unwrap();

        let evpoll_events_len = 10;
        let mut events = Vec::<epoll::Event>::with_capacity(evpoll_events_len);
        // Safe as we pass to set_len the value passed to with_capacity.
        unsafe { events.set_len(evpoll_events_len) };

        // raise the event
        assert!(epev.event_fd.write(1).is_ok());

        // epoll should report one event
        let epollret = epoll::wait(ep.epoll_raw_fd, 0, &mut events[..]);
        let num_events = epollret.unwrap();
        assert_eq!(num_events, 1);

        // removing event should work
        assert!(ep.remove_event(epev).is_ok());

        // reported event should no longer be available
        let idx = events[0].data() as usize;
        assert!(ep.dispatch_table[idx].is_none());
    }
}

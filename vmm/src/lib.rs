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
use api_server::request::sync::{DriveError, GenerateResponse, PutDriveOutcome, SyncRequest};
use api_server::request::sync::boot_source::{PutBootSourceConfigError, PutBootSourceOutcome};
use api_server::request::sync::machine_configuration::PutMachineConfigurationOutcome;
use device_config::*;
use device_manager::*;
use devices::virtio;
use devices::{DeviceEventT, EpollHandler};
use kvm::*;
use machine::MachineCfg;
use sys_util::{register_signal_handler, EventFd, GuestAddress, GuestMemory, Killable, Terminal};
use vm_control::VmResponse;
use vstate::{Vcpu, Vm};

pub const KERNEL_START_OFFSET: usize = 0x200000;
pub const CMDLINE_OFFSET: usize = 0x20000;
pub const CMDLINE_MAX_SIZE: usize = KERNEL_START_OFFSET - CMDLINE_OFFSET;
pub const DEFAULT_KERNEL_CMDLINE:&str = "console=ttyS0 noapic reboot=k panic=1 pci=off nomodules";

#[derive(Debug)]
pub enum Error {
    ConfigureSystem(x86_64::Error),
    EpollFd(std::io::Error),
    EventFd(sys_util::Error),
    GuestMemory(sys_util::GuestMemoryError),
    Kernel(std::io::Error),
    KernelLoader(kernel_loader::Error),
    InvalidKernelPath,
    MissingKernelConfig,
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

#[derive(Clone, Copy)]
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

//This should handle epoll related business from now on. A glaring shortcoming of the current
//design is the liberal passing around of raw_fds, and duping of file descriptors. This issue
//will be solved when we also implement device removal.
pub struct EpollContext {
    epoll_raw_fd: RawFd,
    dispatch_table: Vec<EpollDispatch>,
    device_handlers: Vec<MaybeHandler>,
}

impl EpollContext {
    pub fn new() -> Result<Self> {
        let epoll_raw_fd = epoll::create(true).map_err(Error::EpollFd)?;

        Ok(EpollContext {
            epoll_raw_fd,
            dispatch_table: Vec::with_capacity(20),
            device_handlers: Vec::with_capacity(6),
        })
    }

    pub fn add_event_from_rawfd(&mut self, raw_fd: RawFd, token: EpollDispatch) -> Result<()> {
        epoll::ctl(
            self.epoll_raw_fd,
            epoll::EPOLL_CTL_ADD,
            raw_fd,
            epoll::Event::new(epoll::EPOLLIN, self.dispatch_table.len() as u64),
        ).map_err(Error::EpollFd)?;
        self.dispatch_table.push(token);

        Ok(())
    }

    pub fn add_event(&mut self, evfd: &EventFd, token: EpollDispatch) -> Result<()> {
        self.add_event_from_rawfd(evfd.as_raw_fd(), token)
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

pub struct VmmCore {
    pub kill_signaled: Arc<AtomicBool>,
    pub stdio_serial: Arc<Mutex<devices::Serial>>,
    pub vcpu_handles: Vec<thread::JoinHandle<()>>,
    pub exit_evt: EventFd,
    _vm: Vm,
}

pub struct KernelConfig {
    pub cmdline: kernel_cmdline::Cmdline,
    pub kernel_file: File,
    pub kernel_start_addr: GuestAddress,
    pub cmdline_addr: GuestAddress,
}

// This structure should replace MachineCfg; For now it is safer to duplicate the work as the
// net support is not fuully integrated.
pub struct VirtualMachineConfig {
    vcpu_count: u8,
    mem_size_mib: usize,
}

impl Default for VirtualMachineConfig {
    fn default() -> Self {
        VirtualMachineConfig {
            vcpu_count: 1,
            mem_size_mib: 128,
        }
    }
}

pub struct Vmm {
    cfg: MachineCfg,
    vm_config: VirtualMachineConfig,
    core: Option<VmmCore>,
    kernel_config: Option<KernelConfig>,
    // If there is a Root Block Device, this should be added as the first element of the list
    // This is necessary because we want the root to always be mounted on /dev/vda
    block_device_configs: BlockDeviceConfigs,

    /// api resources
    api_event_fd: EventFd,
    epoll_context: EpollContext,

    from_api: Receiver<Box<ApiRequest>>,
}

impl Vmm {
    pub fn new(
        cfg: MachineCfg,
        api_event_fd: EventFd,
        from_api: Receiver<Box<ApiRequest>>,
    ) -> Result<Self> {
        let mut epoll_context = EpollContext::new()?;
        epoll_context
            .add_event(&api_event_fd, EpollDispatch::ApiRequest)
            .expect("cannot add API eventfd to epoll");
        let block_device_configs = BlockDeviceConfigs::new();
        Ok(Vmm {
            cfg,
            vm_config: VirtualMachineConfig::default(),
            core: None,
            kernel_config: None,
            block_device_configs,
            api_event_fd,
            epoll_context,
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

    pub fn put_virtual_machine_configuration(
        &mut self,
        vcpu_count: Option<u8>,
        mem_size_mib: Option<usize>,
    ) {
        if vcpu_count.is_some() {
            self.vm_config.vcpu_count = vcpu_count.unwrap();
        }

        if mem_size_mib.is_some() {
            self.vm_config.mem_size_mib = mem_size_mib.unwrap();
        }
    }

    /// Attach all block devices from the BlockDevicesConfig
    /// If there is no root block device, no other devices are attached.The root device should be
    /// the first to be attached as a way to make sure it ends up on /dev/vda
    /// This function is to be called only from boot_source
    fn attach_block_devices(&mut self, device_manager: &mut DeviceManager) -> Result<()> {
        // If there's no root device, do not attach any other devices
        let block_dev = &self.block_device_configs;
        let kernel_config = match self.kernel_config.as_mut() {
            Some(x) => x,
            None => return Err(Error::MissingKernelConfig),
        };

        if block_dev.has_root_block_device() {
            // this is a simple solution to add a block as a root device; should be improved
            kernel_config.cmdline.insert_str(" root=/dev/vda").unwrap();

            let epoll_context = &mut self.epoll_context;
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
                    .register_mmio(block_box, &mut kernel_config.cmdline)
                    .map_err(Error::RegisterBlock)?;
            }
        }

        Ok(())
    }

    pub fn configure_kernel(&mut self, kernel_config: KernelConfig) {
        self.kernel_config = Some(kernel_config);
    }

    /// only call this from run_vmm() or other functions
    /// that can guarantee single instances
    pub fn boot_kernel(&mut self) -> Result<()> {
        let mem_size = self.vm_config.mem_size_mib << 20;
        let arch_mem_regions = x86_64::arch_memory_regions(mem_size);

        let vcpu_count = self.vm_config.vcpu_count;
        let guest_mem = GuestMemory::new(&arch_mem_regions).map_err(Error::GuestMemory)?;

        /* Instantiating MMIO device manager
        'mmio_base' address has to be an address which is protected by the kernel, in this case
        the start of the x86 specific gap of memory (currently hardcoded at 768MiB)
        */
        let mut device_manager =
            DeviceManager::new(guest_mem.clone(), x86_64::get_32bit_gap_start() as u64);

        self.attach_block_devices(&mut device_manager)?;

        let epoll_context = &mut self.epoll_context;

        let exit_evt = EventFd::new().map_err(Error::EventFd)?;
        epoll_context.add_event(&exit_evt, EpollDispatch::Exit)?;
        epoll_context.add_event_from_rawfd(libc::STDIN_FILENO, EpollDispatch::Stdin)?;

        let kernel_config = match self.kernel_config.as_mut() {
            Some(x) => x,
            None => return Err(Error::MissingKernelConfig),
        };

        if self.cfg.host_ip.is_some() {
            let epoll_config = epoll_context.allocate_virtio_net_tokens();

            let net_box = Box::new(devices::virtio::Net::new(
                self.cfg.host_ip.unwrap(),
                self.cfg.subnet_mask,
                epoll_config,
            ).map_err(Error::NetDeviceNew)?);

            device_manager
                .register_mmio(net_box, &mut kernel_config.cmdline)
                .map_err(Error::RegisterNet)?;
        }

        if let Some(cid) = self.cfg.vsock_guest_cid {
            let epoll_config = epoll_context.allocate_virtio_vsock_tokens();

            let vsock_box = Box::new(devices::virtio::Vsock::new(cid, &guest_mem, epoll_config)
                .map_err(Error::CreateVirtioVsock)?);
            device_manager
                .register_mmio(vsock_box, &mut kernel_config.cmdline)
                .map_err(Error::RegisterMMIOVsockDevice)?;
        }

        let kvm = Kvm::new().map_err(Error::Kvm)?;
        let vm = Vm::new(&kvm, guest_mem).map_err(Error::Vm)?;

        vm.setup().map_err(Error::VmSetup)?;

        for request in device_manager.vm_requests {
            if let VmResponse::Err(e) = request.execute(vm.get_fd()) {
                return Err(Error::DeviceVmRequest(e));
            }
        }

        // This is the easy way out of consuming the value of the kernel_cmdline.
        // TODO: refactor the kernel_cmdline struct in order to have a CString instead of a String.
        let cmdline_cstring = CString::new(kernel_config.cmdline.clone()).unwrap();

        kernel_loader::load_kernel(
            vm.get_memory(),
            kernel_config.kernel_start_addr,
            &mut kernel_config.kernel_file,
        )?;
        kernel_loader::load_cmdline(
            vm.get_memory(),
            kernel_config.cmdline_addr,
            &cmdline_cstring,
        )?;

        x86_64::configure_system(
            vm.get_memory(),
            kernel_config.kernel_start_addr,
            kernel_config.cmdline_addr,
            cmdline_cstring.to_bytes().len() + 1,
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
            vcpu.configure(vcpu_count, kernel_config.kernel_start_addr, &vm)
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

        self.core = Some(VmmCore {
            vcpu_handles,
            kill_signaled,
            stdio_serial,
            exit_evt,
            _vm: vm,
        });

        Ok(())
    }

    fn stop(&mut self) {
        let mut core = match self.core.take() {
            Some(v) => v,
            None => return (),
        };

        let kill_signaled = &core.kill_signaled;
        let vcpu_handles = &mut core.vcpu_handles;
        let extracted_vcpu_handles = std::mem::replace(vcpu_handles, Vec::new());

        kill_signaled.store(true, Ordering::SeqCst);
        for handle in extracted_vcpu_handles {
            match handle.kill(0) {
                Ok(_) => {
                    if let Err(e) = handle.join() {
                        warn!("failed to join vcpu thread: {:?}", e);
                    }
                }
                Err(e) => warn!("failed to kill vcpu thread: {:?}", e),
            }
        }
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
                let dispatch_type = self.epoll_context.dispatch_table[dispatch_idx];

                match dispatch_type {
                    EpollDispatch::Exit => {
                        info!("vcpu requested shutdown");
                        self.core
                            .as_mut()
                            .unwrap()
                            .exit_evt
                            .read()
                            .expect("cannot read exitevent");
                        self.stop();
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
                                let core = self.core.as_mut().unwrap();
                                core.stdio_serial
                                    .lock()
                                    .unwrap()
                                    .queue_input_bytes(&out[..count])
                                    .map_err(Error::Serial)?;
                            }
                        }
                    }
                    EpollDispatch::DeviceHandler(device_idx, device_token) => {
                        let handler = self.epoll_context.get_device_handler(device_idx);
                        handler.handle_event(device_token, events[i].events().bits());
                    }
                    EpollDispatch::ApiRequest => {
                        self.api_event_fd.read().expect("cannot read ");
                        self.run_api_cmd().unwrap_or_else(|_| {
                            warn!("got spurious notification from api thread");
                            ()
                        });
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
                        sender.send(result).expect("one-shot channel closed");
                    }
                    AsyncRequest::StopInstance(sender) => {
                        sender
                            .send(AsyncOutcome::Error(
                                "StopInstance not implemented".to_string(),
                            ))
                            .expect("one-shot channel closed");
                    }
                };
            }
            ApiRequest::Sync(req) => {
                match req {
                    SyncRequest::PutDrive(drive_description, sender) => {
                        match self.put_block_device(BlockDeviceConfig::from(drive_description)) {
                            Ok(_) => sender
                                .send(Box::new(PutDriveOutcome::Created))
                                .map_err(|_| ())
                                .expect("one-shot channel closed"),
                            Err(e) => sender
                                .send(Box::new(e))
                                .map_err(|_| ())
                                .expect("one-shot channel closed"),
                        }
                    }
                    SyncRequest::PutBootSource(boot_source_body, sender) => {
                        // check that the kernel path exists and it is valid
                        let box_response: Box<GenerateResponse + Send> = match boot_source_body
                            .local_image
                        {
                            Some(image) => match File::open(image.kernel_image_path) {
                                Ok(kernel_file) => {
                                    let mut cmdline =
                                        kernel_cmdline::Cmdline::new(CMDLINE_MAX_SIZE);
                                    match cmdline.insert_str(
                                            boot_source_body
                                                .boot_args
                                                .unwrap_or(String::from(DEFAULT_KERNEL_CMDLINE))
                                                ) {
                                            Ok(_) => {
                                                let kernel_config = KernelConfig {
                                                    kernel_file,
                                                    cmdline,
                                                    kernel_start_addr: GuestAddress(KERNEL_START_OFFSET),
                                                    cmdline_addr: GuestAddress(CMDLINE_OFFSET)
                                                };
                                                // if the kernel was already configure, we have an update operation
                                                let outcome = match self.kernel_config {
                                                    Some(_) => PutBootSourceOutcome::Updated,
                                                    None => PutBootSourceOutcome::Created,
                                                };
                                                self.configure_kernel(kernel_config);
                                                Box::new(outcome)
                                            }
                                            Err(_) => Box::new(PutBootSourceConfigError::InvalidKernelCommandLine)
                                        }
                                }
                                Err(_e) => Box::new(PutBootSourceConfigError::InvalidKernelPath),
                            },
                            None => Box::new(PutBootSourceConfigError::InvalidKernelPath),
                        };
                        sender
                            .send(box_response)
                            .map_err(|_| ())
                            .expect("one-shot channel closed");
                    }
                    SyncRequest::PutMachineConfiguration(machine_config_body, sender) => {
                        self.put_virtual_machine_configuration(machine_config_body.vcpu_count, machine_config_body.mem_size_mib);
                        sender.send(Box::new(PutMachineConfigurationOutcome::Updated)).map_err(|_| ()).expect("one-shot channel closed");;
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
        let mut vmm = Vmm::new(cfg, api_event_fd, from_api).expect("cannot create VMM");
        vmm.run_control().expect("VMM thread fail");
        // TODO: maybe offer through API: an instance status reporting error messages (r)
    })
}

extern crate epoll;
extern crate libc;

extern crate api_server;
extern crate data_model;
extern crate devices;
extern crate kernel_loader;
extern crate kvm;
extern crate kvm_sys;
#[macro_use]
extern crate logger;
extern crate net_util;
extern crate num_cpus;
extern crate sys_util;
extern crate x86_64;

pub mod device_config;
pub mod device_manager;
pub mod kernel_cmdline;
mod vm_control;
mod vstate;

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::os::unix::io::{AsRawFd, RawFd};
use std::result;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Barrier, RwLock};
use std::thread;

use api_server::ApiRequest;
use api_server::request::async::{AsyncOutcome, AsyncRequest};
use api_server::request::instance_info::{InstanceInfo, InstanceState};
use api_server::request::sync::{DriveError, Error as SyncError, GenerateResponse,
                                NetworkInterfaceBody, OkStatus as SyncOkStatus, PutDriveOutcome,
                                SyncRequest, VsockJsonBody};
use api_server::request::sync::boot_source::{PutBootSourceConfigError, PutBootSourceOutcome};
use api_server::request::sync::machine_configuration::{PutMachineConfigurationError,
                                                       PutMachineConfigurationOutcome};
use data_model::vm::MachineConfiguration;
use device_config::*;
use device_manager::legacy::LegacyDeviceManager;
use device_manager::mmio::MMIODeviceManager;

use devices::virtio;
use devices::{DeviceEventT, EpollHandler};
use kvm::*;
use sys_util::{register_signal_handler, EventFd, GuestAddress, GuestMemory, Killable, Terminal};
use vm_control::VmResponse;
use vstate::{Vcpu, Vm};

pub const KERNEL_START_OFFSET: usize = 0x200000;
pub const CMDLINE_OFFSET: usize = 0x20000;
pub const CMDLINE_MAX_SIZE: usize = KERNEL_START_OFFSET - CMDLINE_OFFSET;
pub const DEFAULT_KERNEL_CMDLINE: &str = "console=ttyS0 noapic reboot=k panic=1 pci=off nomodules";
const VCPU_RTSIG_OFFSET: u8 = 0;

#[derive(Debug)]
pub enum Error {
    ConfigureSystem(x86_64::Error),
    EpollFd(std::io::Error),
    EventFd(sys_util::Error),
    GuestMemory(sys_util::GuestMemoryError),
    Kernel(std::io::Error),
    KernelCmdLine(kernel_cmdline::Error),
    KernelLoader(kernel_loader::Error),
    InvalidKernelPath,
    MissingKernelConfig,
    Kvm(sys_util::Error),
    Poll(std::io::Error),
    Serial(sys_util::Error),
    StdinHandle(sys_util::Error),
    Terminal(sys_util::Error),
    Vcpu(vstate::Error),
    VcpuConfigure(vstate::Error),
    VcpuSpawn(std::io::Error),
    Vm(vstate::Error),
    VmSetup(vstate::Error),
    CreateLegacyDevice(device_manager::legacy::Error),
    LegacyIOBus(device_manager::legacy::Error),
    RootDiskImage(std::io::Error),
    RootBlockDeviceNew(sys_util::Error),
    RegisterBlock(device_manager::mmio::Error),
    NetDeviceNew(devices::virtio::NetError),
    RegisterNet(device_manager::mmio::Error),
    CreateVirtioVsock(devices::virtio::vhost::Error),
    RegisterMMIOVsockDevice(device_manager::mmio::Error),
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

impl std::convert::From<kernel_cmdline::Error> for Error {
    fn from(e: kernel_cmdline::Error) -> Error {
        Error::RegisterBlock(device_manager::mmio::Error::Cmdline(e))
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

        // initial capacity large enough to hold 1 exit and 1 stdin events, plus 2 queue events
        // for virtio block, another 4 for virtio net and another 2 for vsock. The total is 10
        // elements. Allowing spare capacity to avoid reallocations.
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
        // ignore failure to remove from epoll, only reason for failure is
        // that stdin has closed or changed - in which case we won't get
        // any more events on the original event_fd anyway.
        let _ = epoll::ctl(
            self.epoll_raw_fd,
            epoll::EPOLL_CTL_DEL,
            libc::STDIN_FILENO,
            epoll::Event::new(epoll::EPOLLIN, self.stdin_index),
        ).map_err(Error::EpollFd);
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
    pub cmdline: kernel_cmdline::Cmdline,
    pub kernel_file: File,
    pub kernel_start_addr: GuestAddress,
    pub cmdline_addr: GuestAddress,
}

pub struct Vmm {
    _kvm_fd: Kvm,

    vm_config: MachineConfiguration,
    shared_info: Arc<RwLock<InstanceInfo>>,

    /// guest VM core resources
    guest_memory: Option<GuestMemory>,
    kernel_config: Option<KernelConfig>,
    kill_signaled: Option<Arc<AtomicBool>>,
    vcpu_handles: Option<Vec<thread::JoinHandle<()>>>,
    exit_evt: Option<EpollEvent>,
    vm: Vm,

    /// guest VM devices
    mmio_device_manager: Option<MMIODeviceManager>,
    legacy_device_manager: LegacyDeviceManager,

    // If there is a Root Block Device, this should be added as the first element of the list
    // This is necessary because we want the root to always be mounted on /dev/vda
    block_device_configs: BlockDeviceConfigs,
    network_interface_configs: NetworkInterfaceConfigs,
    vsock_device_configs: VsockDeviceConfigs,

    epoll_context: EpollContext,

    /// api resources
    api_event: EpollEvent,
    from_api: Receiver<Box<ApiRequest>>,
}

impl Vmm {
    pub fn new(
        api_shared_info: Arc<RwLock<InstanceInfo>>,
        api_event_fd: EventFd,
        from_api: Receiver<Box<ApiRequest>>,
    ) -> Result<Self> {
        let mut epoll_context = EpollContext::new()?;
        // if this fails, it's fatal, .expect() it
        let api_event = epoll_context
            .add_event(api_event_fd, EpollDispatch::ApiRequest)
            .expect("cannot add API eventfd to epoll");
        let block_device_configs = BlockDeviceConfigs::new();
        let kvm_fd = Kvm::new().map_err(Error::Kvm)?;
        let vm = Vm::new(&kvm_fd).map_err(Error::Vm)?;

        Ok(Vmm {
            _kvm_fd: kvm_fd,
            vm_config: MachineConfiguration::default(),
            shared_info: api_shared_info,
            guest_memory: None,
            kernel_config: None,
            kill_signaled: None,
            vcpu_handles: None,
            exit_evt: None,
            vm,
            mmio_device_manager: None,
            legacy_device_manager: LegacyDeviceManager::new()
                .map_err(|e| Error::CreateLegacyDevice(e))?,
            block_device_configs,
            network_interface_configs: NetworkInterfaceConfigs::new(),
            vsock_device_configs: VsockDeviceConfigs::new(),
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

    pub fn put_virtual_machine_configuration(
        &mut self,
        vcpu_count: Option<u8>,
        mem_size_mib: Option<usize>,
    ) -> std::result::Result<(), PutMachineConfigurationError> {
        if vcpu_count.is_some() {
            let vcpu_count_value = vcpu_count.unwrap();
            // Only allow the number of vcpus to be 1 or an even value
            // This is needed for creating a meaningful CPU topology (already enforced by the
            // API call, but still here to avoid future mistakes)
            if vcpu_count_value == 0 || (vcpu_count_value != 1 && vcpu_count_value % 2 == 1)
                || vcpu_count_value > num_cpus::get() as u8
            {
                return Err(PutMachineConfigurationError::InvalidVcpuCount);
            }
            self.vm_config.vcpu_count = vcpu_count;
        }

        if mem_size_mib.is_some() {
            // TODO: add other memory checks
            let mem_size_mib_value = mem_size_mib.unwrap();
            if mem_size_mib_value == 0 {
                return Err(PutMachineConfigurationError::InvalidMemorySize);
            }
            self.vm_config.mem_size_mib = mem_size_mib;
        }

        Ok(())
    }

    /// Attach all block devices from the BlockDevicesConfig
    /// If there is no root block device, no other devices are attached.The root device should be
    /// the first to be attached as a way to make sure it ends up on /dev/vda
    /// This function is to be called only from boot_source
    fn attach_block_devices(&mut self, device_manager: &mut MMIODeviceManager) -> Result<()> {
        // If there's no root device, do not attach any other devices
        let block_dev = &self.block_device_configs;
        let kernel_config = match self.kernel_config.as_mut() {
            Some(x) => x,
            None => return Err(Error::MissingKernelConfig),
        };

        if block_dev.has_root_block_device() {
            // this is a simple solution to add a block as a root device; should be improved
            kernel_config.cmdline.insert_str(" root=/dev/vda")?;
            if block_dev.has_read_only_root() {
                kernel_config.cmdline.insert_str(" ro")?;
            }

            let epoll_context = &mut self.epoll_context;
            for drive_config in self.block_device_configs.config_list.iter() {
                // adding root blk device from file
                let root_image = OpenOptions::new()
                    .read(true)
                    .write(!drive_config.is_read_only)
                    .open(&drive_config.path_on_host)
                    .map_err(Error::RootDiskImage)?;
                let epoll_config = epoll_context.allocate_virtio_block_tokens();

                let block_box = Box::new(devices::virtio::Block::new(
                    root_image,
                    drive_config.is_read_only,
                    epoll_config,
                ).map_err(Error::RootBlockDeviceNew)?);
                device_manager
                    .register_device(block_box, &mut kernel_config.cmdline)
                    .map_err(Error::RegisterBlock)?;
            }
        }

        Ok(())
    }

    pub fn put_net_device(
        &mut self,
        body: NetworkInterfaceBody,
    ) -> result::Result<SyncOkStatus, SyncError> {
        self.network_interface_configs.put(body)
    }

    fn attach_net_devices(&mut self, device_manager: &mut MMIODeviceManager) -> Result<()> {
        let kernel_config = match self.kernel_config.as_mut() {
            Some(x) => x,
            None => return Err(Error::MissingKernelConfig),
        };

        for cfg in self.network_interface_configs.iter_mut() {
            let epoll_config = self.epoll_context.allocate_virtio_net_tokens();
            // The following take_tap() should only be called once, on valid NetworkInterfaceConfig
            // objects, so the unwrap() shouldn't panic.
            let net_box = Box::new(devices::virtio::Net::new_with_tap(
                cfg.take_tap().unwrap(),
                cfg.guest_mac(),
                epoll_config,
            ).map_err(Error::NetDeviceNew)?);

            device_manager
                .register_device(net_box, &mut kernel_config.cmdline)
                .map_err(Error::RegisterNet)?;
        }
        Ok(())
    }

    pub fn put_vsock_device(
        &mut self,
        body: VsockJsonBody,
    ) -> result::Result<SyncOkStatus, SyncError> {
        self.vsock_device_configs.put(body)
    }

    fn attach_vsock_devices(
        &mut self,
        guest_mem: &GuestMemory,
        device_manager: &mut MMIODeviceManager,
    ) -> Result<()> {
        let kernel_config = match self.kernel_config.as_mut() {
            Some(x) => x,
            None => return Err(Error::MissingKernelConfig),
        };

        for cfg in self.vsock_device_configs.iter() {
            let epoll_config = self.epoll_context.allocate_virtio_vsock_tokens();

            let vsock_box = Box::new(devices::virtio::Vsock::new(
                cfg.get_guest_cid() as u64,
                guest_mem,
                epoll_config,
            ).map_err(Error::CreateVirtioVsock)?);
            device_manager
                .register_device(vsock_box, &mut kernel_config.cmdline)
                .map_err(Error::RegisterMMIOVsockDevice)?;
        }

        Ok(())
    }

    pub fn configure_kernel(&mut self, kernel_config: KernelConfig) {
        self.kernel_config = Some(kernel_config);
    }

    pub fn init_guest_memory(&mut self) -> Result<()> {
        // safe to unwrap because vm_config it is initialized with a default value
        let mem_size = self.vm_config.mem_size_mib.unwrap() << 20;
        let arch_mem_regions = x86_64::arch_memory_regions(mem_size);
        self.guest_memory = Some(GuestMemory::new(&arch_mem_regions).map_err(Error::GuestMemory)?);
        Ok(())
    }

    pub fn check_health(&self) -> Result<()> {
        if self.kernel_config.is_none() {
            return Err(Error::MissingKernelConfig);
        }
        Ok(())
    }

    pub fn init_devices(&mut self) -> Result<()> {
        let guest_mem = self.guest_memory.clone().unwrap();
        /* Instantiating MMIO device manager
       'mmio_base' address has to be an address which is protected by the kernel, in this case
       the start of the x86 specific gap of memory (currently hardcoded at 768MiB)
       */
        let mut device_manager =
            MMIODeviceManager::new(guest_mem.clone(), x86_64::get_32bit_gap_start() as u64);

        self.attach_block_devices(&mut device_manager)?;
        self.attach_net_devices(&mut device_manager)?;
        self.attach_vsock_devices(&guest_mem, &mut device_manager)?;

        self.mmio_device_manager = Some(device_manager);
        Ok(())
    }

    pub fn init_microvm(&mut self) -> Result<()> {
        self.vm
            .memory_init(self.guest_memory.clone().unwrap())
            .map_err(Error::VmSetup)?;
        self.vm
            .setup_irqchip(
                &self.legacy_device_manager.com_evt_1_3,
                &self.legacy_device_manager.com_evt_2_4,
            )
            .map_err(Error::VmSetup)?;
        self.vm.create_pit().map_err(Error::VmSetup)?;

        let device_manager = self.mmio_device_manager.as_ref().unwrap();
        for request in &device_manager.vm_requests {
            if let VmResponse::Err(e) = request.execute(self.vm.get_fd()) {
                return Err(Error::DeviceVmRequest(e));
            }
        }

        self.legacy_device_manager
            .register_devices()
            .map_err(Error::LegacyIOBus)?;

        Ok(())
    }

    pub fn start_vcpus(&mut self) -> Result<()> {
        // safe to unwrap because vm_config has a default value for vcpu_count
        let vcpu_count = self.vm_config.vcpu_count.unwrap();
        self.vcpu_handles = Some(Vec::with_capacity(vcpu_count as usize));
        // safe to unwrap since it's set just above
        let vcpu_handles = self.vcpu_handles.as_mut().unwrap();
        self.kill_signaled = Some(Arc::new(AtomicBool::new(false)));
        // safe to unwrap since it's set just above
        let kill_signaled = self.kill_signaled.as_mut().unwrap();

        let vcpu_thread_barrier = Arc::new(Barrier::new((vcpu_count + 1) as usize));

        for cpu_id in 0..vcpu_count {
            let io_bus = self.legacy_device_manager.io_bus.clone();
            let device_manager = self.mmio_device_manager.as_ref().unwrap();
            let mmio_bus = device_manager.bus.clone();
            let kill_signaled = kill_signaled.clone();
            let vcpu_thread_barrier = vcpu_thread_barrier.clone();
            let vcpu_exit_evt = self.legacy_device_manager
                .i8042
                .lock()
                .unwrap()
                .get_eventfd_clone()
                .unwrap();

            let mut vcpu = Vcpu::new(cpu_id, &self.vm).map_err(Error::Vcpu)?;
            let kernel_config = self.kernel_config.as_mut().unwrap();
            vcpu.configure(vcpu_count, kernel_config.kernel_start_addr, &self.vm)
                .map_err(Error::VcpuConfigure)?;
            vcpu_handles.push(thread::Builder::new()
                .name(format!("fc_vcpu{}", cpu_id))
                .spawn(move || {
                    unsafe {
                        extern "C" fn handle_signal() {}
                        // async signal safe handler used to kill the vcpu handles.
                        register_signal_handler(VCPU_RTSIG_OFFSET, handle_signal)
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
    }

    pub fn load_kernel(&mut self) -> Result<()> {
        // This is the easy way out of consuming the value of the kernel_cmdline.
        // TODO: refactor the kernel_cmdline struct in order to have a CString instead of a String.
        // safe to unwrap since we've already validated that the kernel_config has a value
        // in the check_health function
        let kernel_config = self.kernel_config.as_mut().unwrap();
        let cmdline_cstring = CString::new(kernel_config.cmdline.clone())
            .map_err(|_| Error::KernelCmdLine(kernel_cmdline::Error::InvalidAscii))?;

        // Safe to unwrap because the VM memory was initialized before in vm.memory_init()
        let vm_memory = self.vm.get_memory().unwrap();
        kernel_loader::load_kernel(
            vm_memory,
            kernel_config.kernel_start_addr,
            &mut kernel_config.kernel_file,
        )?;
        kernel_loader::load_cmdline(vm_memory, kernel_config.cmdline_addr, &cmdline_cstring)?;

        x86_64::configure_system(
            vm_memory,
            kernel_config.kernel_start_addr,
            kernel_config.cmdline_addr,
            cmdline_cstring.to_bytes().len() + 1,
            self.vm_config.vcpu_count.unwrap(),
        )?;

        Ok(())
    }

    pub fn register_events(&mut self) -> Result<()> {
        let event_fd = self.legacy_device_manager
            .i8042
            .lock()
            .unwrap()
            .get_eventfd_clone()
            .unwrap();
        let exit_epoll_evt = self.epoll_context.add_event(event_fd, EpollDispatch::Exit)?;
        self.exit_evt = Some(exit_epoll_evt);

        self.epoll_context.enable_stdin_event()?;

        Ok(())
    }

    /// make sure to check Result of this function and call self.stop() in case of Err
    pub fn start_instance(&mut self) -> Result<()> {
        self.check_health()?;

        // unwrap() to crash if the other thread poisoned this lock
        self.shared_info.write().unwrap().state = InstanceState::Starting;

        self.init_guest_memory()?;

        self.init_devices()?;
        self.init_microvm()?;

        self.load_kernel()?;

        self.register_events()?;
        self.start_vcpus()?;

        // unwrap() to crash if the other thread poisoned this lock
        self.shared_info.write().unwrap().state = InstanceState::Running;

        Ok(())
    }

    pub fn stop(&mut self) -> Result<()> {
        // unwrap() to crash if the other thread poisoned this lock
        let mut shared_info = self.shared_info.write().unwrap();
        shared_info.state = InstanceState::Halting;

        if let Some(v) = self.kill_signaled.take() {
            v.store(true, Ordering::SeqCst);
        };

        if let Some(handles) = self.vcpu_handles.take() {
            for handle in handles {
                match handle.kill(VCPU_RTSIG_OFFSET) {
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
        self.legacy_device_manager
            .stdin_handle
            .lock()
            .set_canon_mode()
            .map_err(Error::StdinHandle)?;

        //TODO:
        // - clean epoll_context:
        //   - remove block, net

        shared_info.state = InstanceState::Halted;

        Ok(())
    }

    pub fn run_control(&mut self, api_enabled: bool) -> Result<()> {
        const EPOLL_EVENTS_LEN: usize = 100;

        let mut events = Vec::<epoll::Event>::with_capacity(EPOLL_EVENTS_LEN);
        // Safe as we pass to set_len the value passed to with_capacity.
        unsafe { events.set_len(EPOLL_EVENTS_LEN) };

        let epoll_raw_fd = self.epoll_context.epoll_raw_fd;

        // TODO: try handling of errors/failures without breaking this main loop.
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
                            if !api_enabled {
                                break 'poll;
                            }
                        }
                        EpollDispatch::Stdin => {
                            let mut out = [0u8; 64];
                            let stdin_lock = self.legacy_device_manager.stdin_handle.lock();
                            match stdin_lock.read_raw(&mut out[..]) {
                                Ok(0) => {
                                    // Zero-length read indicates EOF. Remove from pollables.
                                    self.epoll_context.disable_stdin_event()?;
                                }
                                Err(e) => {
                                    warn!("error while reading stdin: {:?}", e);
                                    self.epoll_context.disable_stdin_event()?;
                                }
                                Ok(count) => {
                                    // unwrap() to panic if another thread panicked
                                    // while holding the lock
                                    self.legacy_device_manager
                                        .stdio_serial
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
                        let instance_state = {
                            // unwrap() to crash if the other thread poisoned this lock
                            let shared_info = self.shared_info.read().unwrap();
                            shared_info.state.clone()
                        };
                        let result = match instance_state {
                            InstanceState::Starting
                            | InstanceState::Running
                            | InstanceState::Halting => {
                                AsyncOutcome::Error("Guest Instance already running.".to_string())
                            }
                            _ => match self.start_instance() {
                                Ok(_) => AsyncOutcome::Ok(0),
                                Err(e) => {
                                    let _ = self.stop();
                                    AsyncOutcome::Error(format!("cannot boot kernel: {:?}", e))
                                }
                            },
                        };
                        // doing expect() to crash this thread as well if the other thread crashed
                        sender.send(result).expect("one-shot channel closed");
                    }
                    AsyncRequest::StopInstance(sender) => {
                        let result = match self.stop() {
                            Ok(_) => AsyncOutcome::Ok(0),
                            Err(e) => AsyncOutcome::Error(format!(
                                "Errors detected during instance stop()! err: {:?}",
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
                    SyncRequest::GetMachineConfiguration(sender) => {
                        sender
                            .send(Box::new(self.vm_config.clone()))
                            .map_err(|_| ())
                            .expect("one-shot channel closed");
                    }
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
                                            .unwrap_or(String::from(DEFAULT_KERNEL_CMDLINE)),
                                    ) {
                                        Ok(_) => {
                                            let kernel_config = KernelConfig {
                                                kernel_file,
                                                cmdline,
                                                kernel_start_addr: GuestAddress(
                                                    KERNEL_START_OFFSET,
                                                ),
                                                cmdline_addr: GuestAddress(CMDLINE_OFFSET),
                                            };
                                            // if the kernel was already configure, we have an update operation
                                            let outcome = match self.kernel_config {
                                                Some(_) => PutBootSourceOutcome::Updated,
                                                None => PutBootSourceOutcome::Created,
                                            };
                                            self.configure_kernel(kernel_config);
                                            Box::new(outcome)
                                        }
                                        Err(_) => Box::new(
                                            PutBootSourceConfigError::InvalidKernelCommandLine,
                                        ),
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
                        let boxed_response = match self.put_virtual_machine_configuration(
                            machine_config_body.vcpu_count,
                            machine_config_body.mem_size_mib,
                        ) {
                            Ok(_) => Box::new(PutMachineConfigurationOutcome::Updated),
                            Err(e) => Box::new(PutMachineConfigurationOutcome::Error(e)),
                        };

                        sender
                            .send(boxed_response)
                            .map_err(|_| ())
                            .expect("one-shot channel closed");;
                    }
                    SyncRequest::PutNetworkInterface(body, outcome_sender) => outcome_sender
                        .send(Box::new(self.put_net_device(body)))
                        .map_err(|_| ())
                        .expect("one-shot channel closed"),
                    SyncRequest::PutVsock(body, outcome_sender) => outcome_sender
                        .send(Box::new(self.put_vsock_device(body)))
                        .map_err(|_| ())
                        .expect("one-shot channel closed"),
                }
            }
        }

        Ok(())
    }
}

pub fn start_vmm_thread(
    api_shared_info: Arc<RwLock<InstanceInfo>>,
    api_event_fd: EventFd,
    from_api: Receiver<Box<ApiRequest>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        // if this fails, consider it fatal: .expect()
        let mut vmm = Vmm::new(api_shared_info, api_event_fd, from_api).expect("cannot create VMM");
        let r = vmm.run_control(true);
        // make sure we clean up when this loop breaks on error
        if r.is_err() {
            // stop() is safe to call at any moment; ignore the result
            let _ = vmm.stop();
        }
        // vmm thread errors are irrecoverable for now: .expect()
        r.expect("VMM thread fail");
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
        assert_eq!(
            *ep.dispatch_table[idx].as_ref().unwrap(),
            EpollDispatch::Exit
        );

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

extern crate epoll;
extern crate libc;
extern crate serde_json;
extern crate timerfd;

extern crate api_server;
extern crate data_model;
extern crate devices;
extern crate kernel_loader;
extern crate kvm;
extern crate kvm_sys;
#[macro_use]
extern crate logger;
extern crate net_util;
extern crate sys_util;
extern crate x86_64;

mod api_logger_config;
mod device_config;
mod device_manager;
pub mod kernel_cmdline;
mod vm_control;
mod vstate;

use std::ffi::CString;
use std::fs::{metadata, File, OpenOptions};
use std::os::unix::io::{AsRawFd, RawFd};
use std::result;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Barrier, RwLock};
use std::thread;
use std::time;

use libc::{c_void, siginfo_t};
use serde_json::Value;
use timerfd::{ClockId, SetTimeFlags, TimerFd, TimerState};

use api_server::request::actions::ActionBody;
use api_server::request::async::{AsyncOutcome, AsyncOutcomeSender, AsyncRequest};
use api_server::request::instance_info::{InstanceInfo, InstanceState};
use api_server::request::sync::boot_source::{PutBootSourceConfigError, PutBootSourceOutcome};
use api_server::request::sync::machine_configuration::{
    PutMachineConfigurationError, PutMachineConfigurationOutcome,
};
use api_server::request::sync::{
    APILoggerDescription, BootSourceBody, DriveDescription, DriveError, Error as SyncError,
    GenerateResponse, NetworkInterfaceBody, OkStatus as SyncOkStatus, PutDriveOutcome,
    PutLoggerOutcome, SyncOutcomeSender, SyncRequest,
};
use api_server::ApiRequest;
use data_model::vm::description_into_implementation as rate_limiter_description_into_implementation;
use data_model::vm::MachineConfiguration;
use device_config::*;
use device_manager::legacy::LegacyDeviceManager;
use device_manager::mmio::MMIODeviceManager;
use devices::virtio;
use devices::{DeviceEventT, EpollHandler};
use kvm::*;
use logger::{Metric, LOGGER, METRICS};
use sys_util::{register_signal_handler, EventFd, GuestAddress, GuestMemory, Killable, Terminal};
use vm_control::VmResponse;
use vstate::{Vcpu, Vm};

const DEFAULT_KERNEL_CMDLINE: &str = "reboot=k panic=1 pci=off nomodules 8250.nr_uarts=0";
const VCPU_RTSIG_OFFSET: i32 = 0;
const WRITE_METRICS_PERIOD_SECONDS: u64 = 60;

#[derive(Debug)]
pub enum Error {
    ApiChannel,
    ConfigureSystem(x86_64::Error),
    CreateBlockDevice(sys_util::Error),
    CreateNetDevice(devices::virtio::Error),
    CreateRateLimiter(std::io::Error),
    CreateLegacyDevice(device_manager::legacy::Error),
    DriveError(DriveError),
    DeviceVmRequest(sys_util::Error),
    EpollFd(std::io::Error),
    EventFd(sys_util::Error),
    GeneralFailure,
    GuestMemory(sys_util::GuestMemoryError),
    InvalidKernelPath,
    Kernel(std::io::Error),
    KernelCmdLine(kernel_cmdline::Error),
    KernelLoader(kernel_loader::Error),
    Kvm(sys_util::Error),
    KvmApiVersion(i32),
    KvmCap(kvm::Cap),
    LegacyIOBus(device_manager::legacy::Error),
    LogMetrics(logger::error::LoggerError),
    MissingKernelConfig,
    NetDeviceUnconfigured,
    OpenBlockDevice(std::io::Error),
    Poll(std::io::Error),
    RegisterBlockDevice(device_manager::mmio::Error),
    RegisterNetDevice(device_manager::mmio::Error),
    Serial(sys_util::Error),
    StdinHandle(sys_util::Error),
    Terminal(sys_util::Error),
    TimerFd(std::io::Error),
    Vcpu(vstate::Error),
    VcpuConfigure(vstate::Error),
    VcpuSpawn(std::io::Error),
    Vm(vstate::Error),
    VmSetup(vstate::Error),
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
        Error::RegisterBlockDevice(device_manager::mmio::Error::Cmdline(e))
    }
}

type Result<T> = std::result::Result<T, Error>;

// Allows access to the functionality of the KVM wrapper only as long as every required
// KVM capability is present on the host.
struct KvmContext {
    kvm: Kvm,
    nr_vcpus: usize,
    max_vcpus: usize,
}

impl KvmContext {
    fn new() -> Result<Self> {
        fn check_cap(kvm: &Kvm, cap: Cap) -> std::result::Result<(), Error> {
            if !kvm.check_extension(cap) {
                return Err(Error::KvmCap(cap));
            }
            Ok(())
        }

        let kvm = Kvm::new().map_err(Error::Kvm)?;

        if kvm.get_api_version() != kvm::KVM_API_VERSION as i32 {
            return Err(Error::KvmApiVersion(kvm.get_api_version()));
        }

        check_cap(&kvm, Cap::Irqchip)?;
        check_cap(&kvm, Cap::Ioeventfd)?;
        check_cap(&kvm, Cap::Irqfd)?;
        // check_cap(&kvm, Cap::ImmediateExit)?;
        check_cap(&kvm, Cap::SetTssAddr)?;
        check_cap(&kvm, Cap::UserMemory)?;

        let nr_vcpus = kvm.get_nr_vcpus();
        let max_vcpus = match kvm.check_extension_int(Cap::MaxVcpus) {
            0 => nr_vcpus,
            x => x as usize,
        };

        Ok(KvmContext {
            kvm,
            nr_vcpus,
            max_vcpus,
        })
    }

    fn fd(&self) -> &Kvm {
        &self.kvm
    }

    #[allow(dead_code)]
    fn nr_vcpus(&self) -> usize {
        self.nr_vcpus
    }

    #[allow(dead_code)]
    fn max_vcpus(&self) -> usize {
        self.max_vcpus
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum EpollDispatch {
    Exit,
    Stdin,
    DeviceHandler(usize, DeviceEventT),
    ApiRequest,
    WriteMetrics,
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

struct EpollEvent<T: AsRawFd> {
    dispatch_index: u64,
    fd: T,
}

// Handles epoll related business.
// A glaring shortcoming of the current design is the liberal passing around of raw_fds,
// and duping of file descriptors. This issue will be solved when we also implement device removal.
struct EpollContext {
    epoll_raw_fd: RawFd,
    stdin_index: u64,
    // FIXME: find a different design as this does not scale. This Vec can only grow.
    dispatch_table: Vec<Option<EpollDispatch>>,
    device_handlers: Vec<MaybeHandler>,
}

impl EpollContext {
    fn new() -> Result<Self> {
        let epoll_raw_fd = epoll::create(true).map_err(Error::EpollFd)?;

        // Initial capacity needs to be large enough to hold:
        // * 1 exit event
        // * 1 stdin event
        // * 2 queue events for virtio block
        // * 4 for virtio net
        // The total is 8 elements; allowing spare capacity to avoid reallocations.
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

    fn enable_stdin_event(&mut self) -> Result<()> {
        epoll::ctl(
            self.epoll_raw_fd,
            epoll::EPOLL_CTL_ADD,
            libc::STDIN_FILENO,
            epoll::Event::new(epoll::EPOLLIN, self.stdin_index),
        ).map_err(Error::EpollFd)?;
        self.dispatch_table[self.stdin_index as usize] = Some(EpollDispatch::Stdin);

        Ok(())
    }

    fn disable_stdin_event(&mut self) -> Result<()> {
        // Ignore failure to remove from epoll. The only reason for failure is
        // that stdin has closed or changed in which case we won't get
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

    fn add_event<T>(&mut self, fd: T, token: EpollDispatch) -> Result<EpollEvent<T>>
    where
        T: AsRawFd,
    {
        let dispatch_index = self.dispatch_table.len() as u64;
        epoll::ctl(
            self.epoll_raw_fd,
            epoll::EPOLL_CTL_ADD,
            fd.as_raw_fd(),
            epoll::Event::new(epoll::EPOLLIN, dispatch_index),
        ).map_err(Error::EpollFd)?;
        self.dispatch_table.push(Some(token));

        Ok(EpollEvent { dispatch_index, fd })
    }

    fn remove_event<T>(&mut self, epoll_event: EpollEvent<T>) -> Result<()>
    where
        T: AsRawFd,
    {
        epoll::ctl(
            self.epoll_raw_fd,
            epoll::EPOLL_CTL_DEL,
            epoll_event.fd.as_raw_fd(),
            epoll::Event::new(epoll::EPOLLIN, epoll_event.dispatch_index),
        ).map_err(Error::EpollFd)?;
        self.dispatch_table[epoll_event.dispatch_index as usize] = None;

        Ok(())
    }

    fn allocate_tokens(&mut self, count: usize) -> (u64, Sender<Box<EpollHandler>>) {
        let dispatch_base = self.dispatch_table.len() as u64;
        let device_idx = self.device_handlers.len();
        let (sender, receiver) = channel();

        for x in 0..count {
            self.dispatch_table.push(Some(EpollDispatch::DeviceHandler(
                device_idx,
                x as DeviceEventT,
            )));
        }

        self.device_handlers.push(MaybeHandler::new(receiver));

        (dispatch_base, sender)
    }

    fn allocate_virtio_block_tokens(&mut self) -> virtio::block::EpollConfig {
        let (dispatch_base, sender) = self.allocate_tokens(virtio::block::BLOCK_EVENTS_COUNT);
        virtio::block::EpollConfig::new(dispatch_base, self.epoll_raw_fd, sender)
    }

    fn allocate_virtio_net_tokens(&mut self) -> virtio::net::EpollConfig {
        let (dispatch_base, sender) = self.allocate_tokens(virtio::net::NET_EVENTS_COUNT);
        virtio::net::EpollConfig::new(dispatch_base, self.epoll_raw_fd, sender)
    }

    fn get_device_handler(&mut self, device_idx: usize) -> Result<&mut EpollHandler> {
        let ref mut maybe = self.device_handlers[device_idx];
        match maybe.handler {
            Some(ref mut v) => Ok(v.as_mut()),
            None => {
                // This should only be called in response to an epoll trigger.
                // Moreover, this branch of the match should only be active on the first call
                // (the first epoll event for this device), therefore the channel is guaranteed
                // to contain a message for the first epoll event since both epoll event
                // registration and channel send() happen in the device activate() function.
                let received = maybe
                    .receiver
                    .try_recv()
                    .map_err(|_| Error::GeneralFailure)?;
                Ok(maybe.handler.get_or_insert(received).as_mut())
            }
        }
    }
}

impl Drop for EpollContext {
    fn drop(&mut self) {
        let rc = unsafe { libc::close(self.epoll_raw_fd) };
        if rc != 0 {
            warn!("Cannot close epoll.");
        }
    }
}

pub struct KernelConfig {
    cmdline: kernel_cmdline::Cmdline,
    kernel_file: File,
    cmdline_addr: GuestAddress,
}

pub struct Vmm {
    _kvm: KvmContext,

    vm_config: MachineConfiguration,
    shared_info: Arc<RwLock<InstanceInfo>>,

    // guest VM core resources
    guest_memory: Option<GuestMemory>,
    kernel_config: Option<KernelConfig>,
    kill_signaled: Option<Arc<AtomicBool>>,
    vcpu_handles: Option<Vec<thread::JoinHandle<()>>>,
    exit_evt: Option<EpollEvent<EventFd>>,
    vm: Vm,

    // guest VM devices
    mmio_device_manager: Option<MMIODeviceManager>,
    legacy_device_manager: LegacyDeviceManager,

    // If there is a Root Block Device, this should be added as the first element of the list
    // This is necessary because we want the root to always be mounted on /dev/vda
    block_device_configs: BlockDeviceConfigs,
    network_interface_configs: NetworkInterfaceConfigs,

    epoll_context: EpollContext,

    // api resources
    api_event: EpollEvent<EventFd>,
    from_api: Receiver<Box<ApiRequest>>,

    write_metrics_event: EpollEvent<TimerFd>,
}

impl Vmm {
    fn new(
        api_shared_info: Arc<RwLock<InstanceInfo>>,
        api_event_fd: EventFd,
        from_api: Receiver<Box<ApiRequest>>,
    ) -> Result<Self> {
        let mut epoll_context = EpollContext::new()?;
        // If this fails, it's fatal; using expect() to crash.
        let api_event = epoll_context
            .add_event(api_event_fd, EpollDispatch::ApiRequest)
            .expect("Cannot add API eventfd to epoll.");

        let write_metrics_event = epoll_context
            .add_event(
                // non-blocking & close on exec
                TimerFd::new_custom(ClockId::Monotonic, true, true).map_err(Error::TimerFd)?,
                EpollDispatch::WriteMetrics,
            )
            .expect("Cannot add write metrics TimerFd to epoll.");

        let block_device_configs = BlockDeviceConfigs::new();
        let kvm = KvmContext::new()?;
        let vm = Vm::new(kvm.fd()).map_err(Error::Vm)?;

        Ok(Vmm {
            _kvm: kvm,
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
            epoll_context,
            api_event,
            from_api,
            write_metrics_event,
        })
    }

    // Only call this function as part of the API.
    // If the drive_id does not exist, a new Block Device Config is added to the list.
    // Else, if the VM is running, the block device will be updated.
    // Updating before the VM has started is not allowed.
    fn put_block_device(
        &mut self,
        block_device_config: BlockDeviceConfig,
    ) -> result::Result<PutDriveOutcome, DriveError> {
        // If the id of the drive already exists in the list, the operation is update.
        if self
            .block_device_configs
            .contains_drive_id(block_device_config.drive_id.clone())
        {
            return self.update_block_device(&block_device_config);
        } else {
            match self.block_device_configs.add(block_device_config) {
                Ok(_) => Ok(PutDriveOutcome::Created),
                Err(e) => Err(e),
            }
        }
    }

    fn update_block_device(
        &mut self,
        block_device_config: &BlockDeviceConfig,
    ) -> result::Result<PutDriveOutcome, DriveError> {
        if self.mmio_device_manager.is_some() {
            Err(DriveError::BlockDeviceUpdateNotAllowed)
        } else {
            self.block_device_configs
                .update(block_device_config)
                .map(|_| PutDriveOutcome::Updated)
        }
    }

    fn put_virtual_machine_configuration(
        &mut self,
        machine_config: MachineConfiguration,
    ) -> std::result::Result<(), PutMachineConfigurationError> {
        if let Some(vcpu_count_value) = machine_config.vcpu_count {
            // Check that the vcpu_count value is >=1.
            if vcpu_count_value <= 0 {
                return Err(PutMachineConfigurationError::InvalidVcpuCount);
            }
        }

        if let Some(mem_size_mib_value) = machine_config.mem_size_mib {
            // TODO: add other memory checks
            if mem_size_mib_value <= 0 {
                return Err(PutMachineConfigurationError::InvalidMemorySize);
            }
        }

        let ht_enabled = match machine_config.ht_enabled {
            Some(value) => value,
            None => self.vm_config.ht_enabled.unwrap(),
        };

        let vcpu_count_value = match machine_config.vcpu_count {
            Some(value) => value,
            None => self.vm_config.vcpu_count.unwrap(),
        };

        // If hyperthreading is enabled or is to be enabled in this call
        // only allow vcpu count to be 1 or even.
        if ht_enabled && vcpu_count_value > 1 && vcpu_count_value % 2 == 1 {
            return Err(PutMachineConfigurationError::InvalidVcpuCount);
        }

        // Update all the fields that have a new value.
        self.vm_config.vcpu_count = Some(vcpu_count_value);
        self.vm_config.ht_enabled = Some(ht_enabled);

        if machine_config.mem_size_mib.is_some() {
            self.vm_config.mem_size_mib = machine_config.mem_size_mib;
        }

        if machine_config.cpu_template.is_some() {
            self.vm_config.cpu_template = machine_config.cpu_template;
        }

        Ok(())
    }

    // Attaches all block devices from the BlockDevicesConfig.
    fn attach_block_devices(&mut self, device_manager: &mut MMIODeviceManager) -> Result<()> {
        let block_dev = &self.block_device_configs;
        // We rely on check_health function for making sure kernel_config is not None.
        let kernel_config = self.kernel_config.as_mut().unwrap();

        if block_dev.has_root_block_device() {
            // If no PARTUUID was specified for the root device, try with the /dev/vda.
            if !block_dev.has_partuuid_root() {
                kernel_config.cmdline.insert_str(" root=/dev/vda")?;

                if block_dev.has_read_only_root() {
                    kernel_config.cmdline.insert_str(" ro")?;
                }
            }
        }

        let epoll_context = &mut self.epoll_context;
        for drive_config in self.block_device_configs.config_list.iter() {
            // Add the block device from file.
            let block_file = OpenOptions::new()
                .read(true)
                .write(!drive_config.is_read_only)
                .open(&drive_config.path_on_host)
                .map_err(Error::OpenBlockDevice)?;

            if drive_config.is_root_device && drive_config.get_partuuid().is_some() {
                kernel_config.cmdline.insert_str(format!(
                    " root=PARTUUID={}",
                    //The unwrap is safe as we are firstly checking that partuuid is_some().
                    drive_config.get_partuuid().unwrap()
                ))?;
                if drive_config.is_read_only {
                    kernel_config.cmdline.insert_str(" ro")?;
                }
            }

            let epoll_config = epoll_context.allocate_virtio_block_tokens();

            let rate_limiter = rate_limiter_description_into_implementation(
                drive_config.rate_limiter.as_ref(),
            ).map_err(Error::CreateRateLimiter)?;
            let block_box = Box::new(
                devices::virtio::Block::new(
                    block_file,
                    drive_config.is_read_only,
                    epoll_config,
                    rate_limiter,
                ).map_err(Error::CreateBlockDevice)?,
            );
            device_manager
                .register_device(
                    block_box,
                    &mut kernel_config.cmdline,
                    Some(drive_config.drive_id.clone()),
                )
                .map_err(Error::RegisterBlockDevice)?;
        }

        Ok(())
    }

    fn put_net_device(
        &mut self,
        body: NetworkInterfaceBody,
    ) -> result::Result<SyncOkStatus, SyncError> {
        self.network_interface_configs.put(body)
    }

    fn rescan_block_device(&mut self, body: ActionBody) -> result::Result<SyncOkStatus, SyncError> {
        if let Some(Value::String(drive_id)) = body.payload {
            // Safe to unwrap() because mmio_device_manager is initialized in init_devices(), which is
            // called before the guest boots, and this function is called after boot.
            let device_manager = self.mmio_device_manager.as_ref().unwrap();
            match device_manager.get_address(&drive_id) {
                Some(&address) => {
                    for drive_config in self.block_device_configs.config_list.iter() {
                        if drive_config.drive_id == *drive_id {
                            let metadata = metadata(&drive_config.path_on_host).map_err(|_| {
                                SyncError::DriveOperationFailed(DriveError::BlockDeviceUpdateFailed)
                            })?;
                            let new_size = metadata.len();
                            if new_size % virtio::block::SECTOR_SIZE != 0 {
                                warn!(
                                    "Disk size {} is not a multiple of sector size {}; \
                                     the remainder will not be visible to the guest.",
                                    new_size,
                                    virtio::block::SECTOR_SIZE
                                );
                            }
                            return device_manager
                                .update_drive(address, new_size)
                                .map(|_| SyncOkStatus::Updated)
                                .map_err(|_| {
                                    SyncError::DriveOperationFailed(
                                        DriveError::BlockDeviceUpdateFailed,
                                    )
                                });
                        }
                    }
                    Err(SyncError::DriveOperationFailed(
                        DriveError::BlockDeviceUpdateFailed,
                    ))
                }
                _ => Err(SyncError::DriveOperationFailed(
                    DriveError::InvalidBlockDeviceID,
                )),
            }
        } else {
            Err(SyncError::InvalidPayload)
        }
    }

    fn attach_net_devices(&mut self, device_manager: &mut MMIODeviceManager) -> Result<()> {
        // We rely on check_health function for making sure kernel_config is not None.
        let kernel_config = self.kernel_config.as_mut().unwrap();

        for cfg in self.network_interface_configs.iter_mut() {
            let epoll_config = self.epoll_context.allocate_virtio_net_tokens();

            let rx_rate_limiter = rate_limiter_description_into_implementation(
                cfg.rx_rate_limiter.as_ref(),
            ).map_err(Error::CreateRateLimiter)?;
            let tx_rate_limiter = rate_limiter_description_into_implementation(
                cfg.tx_rate_limiter.as_ref(),
            ).map_err(Error::CreateRateLimiter)?;

            if let Some(tap) = cfg.take_tap() {
                let net_box = Box::new(
                    devices::virtio::Net::new_with_tap(
                        tap,
                        cfg.guest_mac(),
                        epoll_config,
                        rx_rate_limiter,
                        tx_rate_limiter,
                    ).map_err(Error::CreateNetDevice)?,
                );

                device_manager
                    .register_device(net_box, &mut kernel_config.cmdline, None)
                    .map_err(Error::RegisterNetDevice)?;
            } else {
                return Err(Error::NetDeviceUnconfigured);
            }
        }
        Ok(())
    }

    fn configure_kernel(&mut self, kernel_config: KernelConfig) {
        self.kernel_config = Some(kernel_config);
    }

    fn init_guest_memory(&mut self) -> Result<()> {
        // It is safe to unwrap because vm_config it is initialized with a default value.
        let mem_size = self.vm_config.mem_size_mib.unwrap() << 20;
        let arch_mem_regions = x86_64::arch_memory_regions(mem_size);
        self.guest_memory = Some(GuestMemory::new(&arch_mem_regions).map_err(Error::GuestMemory)?);
        Ok(())
    }

    fn check_health(&self) -> Result<()> {
        if self.kernel_config.is_none() {
            return Err(Error::MissingKernelConfig);
        }
        Ok(())
    }

    fn init_devices(&mut self) -> Result<()> {
        let guest_mem = self.guest_memory.clone().ok_or(Error::GuestMemory(
            sys_util::GuestMemoryError::MemoryNotInitialized,
        ))?;
        // Instantiate the MMIO device manager.
        // 'mmio_base' address has to be an address which is protected by the kernel, in this case
        // the start of the x86 specific gap of memory (currently hardcoded at 768MiB).
        let mut device_manager =
            MMIODeviceManager::new(guest_mem.clone(), x86_64::get_32bit_gap_start() as u64);

        self.attach_block_devices(&mut device_manager)?;
        self.attach_net_devices(&mut device_manager)?;

        self.mmio_device_manager = Some(device_manager);
        Ok(())
    }

    fn init_microvm(&mut self) -> Result<()> {
        self.vm
            .memory_init(self.guest_memory.clone().ok_or(Error::VmSetup(
                vstate::Error::GuestMemory(sys_util::GuestMemoryError::MemoryNotInitialized),
            ))?)
            .map_err(Error::VmSetup)?;
        self.vm
            .setup_irqchip(
                &self.legacy_device_manager.com_evt_1_3,
                &self.legacy_device_manager.com_evt_2_4,
            )
            .map_err(Error::VmSetup)?;
        self.vm.create_pit().map_err(Error::VmSetup)?;

        // It is safe to unwrap() because mmio_device_manager is instantiated in init_devices, which
        // is called before init_microvm.
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

    fn start_vcpus(&mut self, entry_addr: GuestAddress) -> Result<()> {
        // It is safe to unwrap because vm_config has a default value for vcpu_count.
        let vcpu_count = self.vm_config.vcpu_count.unwrap();
        self.vcpu_handles = Some(Vec::with_capacity(vcpu_count as usize));
        // It is safe to unwrap since it's set just above.
        let vcpu_handles = self.vcpu_handles.as_mut().unwrap();
        self.kill_signaled = Some(Arc::new(AtomicBool::new(false)));
        // It is safe to unwrap since it's set just above.
        let kill_signaled = self.kill_signaled.as_mut().unwrap();

        let vcpu_thread_barrier = Arc::new(Barrier::new((vcpu_count + 1) as usize));

        for cpu_id in 0..vcpu_count {
            let io_bus = self.legacy_device_manager.io_bus.clone();
            // It is safe to unwrap() because mmio_device_manager is instantiated in init_devices,
            // which is called before start_vcpus.
            let device_manager = self.mmio_device_manager.as_ref().unwrap();
            let mmio_bus = device_manager.bus.clone();
            let kill_signaled = kill_signaled.clone();
            let vcpu_thread_barrier = vcpu_thread_barrier.clone();
            // If the lock is poisoned, it's OK to panic.
            let vcpu_exit_evt = self
                .legacy_device_manager
                .i8042
                .lock()
                .unwrap()
                .get_eventfd_clone()
                .map_err(|_| Error::GeneralFailure)?;

            let mut vcpu = Vcpu::new(cpu_id, &self.vm).map_err(Error::Vcpu)?;

            // It is safe to unwrap the ht_enabled flag because the machine configure
            // has default values for all fields.
            vcpu.configure(&self.vm_config, entry_addr, &self.vm)
                .map_err(Error::VcpuConfigure)?;
            vcpu_handles.push(
                thread::Builder::new()
                    .name(format!("fc_vcpu{}", cpu_id))
                    .spawn(move || {
                        unsafe {
                            extern "C" fn handle_signal(_: i32, _: *mut siginfo_t, _: *mut c_void) {
                            }
                            // This uses an async signal safe handler to kill the vcpu handles.
                            register_signal_handler(
                                VCPU_RTSIG_OFFSET,
                                sys_util::SignalHandler::Siginfo(handle_signal),
                                true,
                            ).expect("Failed to register vcpu signal handler");
                        }

                        vcpu_thread_barrier.wait();

                        loop {
                            match vcpu.run() {
                                Ok(run) => match run {
                                    VcpuExit::IoIn(addr, data) => {
                                        io_bus.read(addr as u64, data);
                                        METRICS.vcpu.exit_io_in.inc();
                                    }
                                    VcpuExit::IoOut(addr, data) => {
                                        io_bus.write(addr as u64, data);
                                        METRICS.vcpu.exit_io_out.inc();
                                    }
                                    VcpuExit::MmioRead(addr, data) => {
                                        mmio_bus.read(addr, data);
                                        METRICS.vcpu.exit_mmio_read.inc();
                                    }
                                    VcpuExit::MmioWrite(addr, data) => {
                                        mmio_bus.write(addr, data);
                                        METRICS.vcpu.exit_mmio_write.inc();
                                    }
                                    VcpuExit::Hlt => {
                                        info!("Received KVM_EXIT_HLT signal");
                                        break;
                                    }
                                    VcpuExit::Shutdown => {
                                        info!("Received KVM_EXIT_SHUTDOWN signal");
                                        break;
                                    }
                                    // Documentation specifies that below kvm exits are considered
                                    // errors.
                                    VcpuExit::FailEntry => {
                                        METRICS.vcpu.failures.inc();
                                        error!("Received KVM_EXIT_FAIL_ENTRY signal");
                                        break;
                                    }
                                    VcpuExit::InternalError => {
                                        METRICS.vcpu.failures.inc();
                                        error!("Received KVM_EXIT_INTERNAL_ERROR signal");
                                        break;
                                    }
                                    r => {
                                        METRICS.vcpu.failures.inc();
                                        // TODO: Are we sure we want to finish running a vcpu upon
                                        // receiving a vm exit that is not necessarily an error?
                                        error!("Unexpected exit reason on vcpu run: {:?}", r);
                                        break;
                                    }
                                },
                                Err(vstate::Error::VcpuRun(ref e)) => match e.errno() {
                                    // Why do we check for these if we only return EINVAL?
                                    libc::EAGAIN | libc::EINTR => {}
                                    _ => {
                                        METRICS.vcpu.failures.inc();
                                        error!("Failure during vcpu run: {:?}", e);
                                        break;
                                    }
                                },
                                _ => (),
                            }

                            if kill_signaled.load(Ordering::SeqCst) {
                                break;
                            }
                        }

                        // Nothing we need do for the success case.
                        if let Err(e) = vcpu_exit_evt.write(1) {
                            METRICS.vcpu.failures.inc();
                            error!("Failed signaling vcpu exit event: {:?}", e);
                        }
                    })
                    .map_err(Error::VcpuSpawn)?,
            );
        }

        vcpu_thread_barrier.wait();

        Ok(())
    }

    fn load_kernel(&mut self) -> Result<GuestAddress> {
        // This is the easy way out of consuming the value of the kernel_cmdline.
        // TODO: refactor the kernel_cmdline struct in order to have a CString instead of a String.
        // It is safe to unwrap since we've already validated that the kernel_config has a value
        // in the check_health function.
        let kernel_config = self.kernel_config.as_mut().unwrap();
        let cmdline_cstring = CString::new(kernel_config.cmdline.clone())
            .map_err(|_| Error::KernelCmdLine(kernel_cmdline::Error::InvalidAscii))?;

        // It is safe to unwrap because the VM memory was initialized before in vm.memory_init().
        let vm_memory = self.vm.get_memory().unwrap();
        let entry_addr = kernel_loader::load_kernel(vm_memory, &mut kernel_config.kernel_file)?;
        kernel_loader::load_cmdline(vm_memory, kernel_config.cmdline_addr, &cmdline_cstring)?;

        x86_64::configure_system(
            vm_memory,
            kernel_config.cmdline_addr,
            cmdline_cstring.to_bytes().len() + 1,
            self.vm_config.vcpu_count.ok_or(Error::GeneralFailure)?,
        )?;
        Ok(entry_addr)
    }

    fn register_events(&mut self) -> Result<()> {
        // If the lock is poisoned, it's OK to panic.
        let event_fd = self
            .legacy_device_manager
            .i8042
            .lock()
            .unwrap()
            .get_eventfd_clone()
            .map_err(|_| Error::GeneralFailure)?;
        let exit_epoll_evt = self.epoll_context.add_event(event_fd, EpollDispatch::Exit)?;
        self.exit_evt = Some(exit_epoll_evt);

        self.epoll_context.enable_stdin_event()?;

        Ok(())
    }

    fn start_instance(&mut self) -> Result<()> {
        info!("VMM received instance start command");
        self.check_health()?;

        // Use unwrap() to crash if the other thread poisoned this lock.
        self.shared_info.write().unwrap().state = InstanceState::Starting;

        self.init_guest_memory()?;

        self.init_devices()?;
        self.init_microvm()?;

        let entry_addr = self.load_kernel()?;

        self.register_events()?;
        self.start_vcpus(entry_addr)?;

        // Use unwrap() to crash if the other thread poisoned this lock.
        self.shared_info.write().unwrap().state = InstanceState::Running;

        // Arm the log write timer.
        // TODO: the timer does not stop on InstanceStop.
        let timer_state = TimerState::Periodic {
            current: time::Duration::from_secs(WRITE_METRICS_PERIOD_SECONDS),
            interval: time::Duration::from_secs(WRITE_METRICS_PERIOD_SECONDS),
        };
        self.write_metrics_event
            .fd
            .set_state(timer_state, SetTimeFlags::Default);

        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        info!("VMM received instance stop command");
        // Use unwrap() to crash if the other thread poisoned this lock.
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
                            warn!("Failed to join vcpu thread: {:?}", e);
                            METRICS.vcpu.failures.inc();
                        }
                    }
                    Err(e) => {
                        METRICS.vcpu.failures.inc();
                        warn!("Failed to kill vcpu thread: {:?}", e)
                    }
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

    fn run_control(&mut self, api_enabled: bool) -> Result<()> {
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
                            match self.exit_evt {
                                Some(ref ev) => {
                                    ev.fd.read().map_err(Error::EventFd)?;
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
                                    // Use unwrap() to panic if another thread panicked
                                    // while holding the lock.
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
                            METRICS.vmm.device_events.inc();
                            match self.epoll_context.get_device_handler(device_idx) {
                                Ok(handler) => {
                                    handler.handle_event(device_token, events[i].events().bits())
                                }
                                Err(e) => {
                                    warn!("invalid handler for device {}: {:?}", device_idx, e)
                                }
                            }
                        }
                        EpollDispatch::ApiRequest => {
                            self.api_event.fd.read().map_err(Error::EventFd)?;
                            self.run_api_cmd().unwrap_or_else(|_| {
                                warn!("got spurious notification from api thread");
                                ()
                            });
                        }
                        EpollDispatch::WriteMetrics => {
                            self.write_metrics_event.fd.read();

                            // Please note that, since LOGGER has no output file configured yet,
                            // it will write to stdout, so metric logging will interfere with
                            // console output.
                            if let Err(e) = LOGGER.log_metrics() {
                                error!("Failed to log metrics: {}", e);
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn handle_start_instance(&mut self, sender: AsyncOutcomeSender) {
        let instance_state = {
            // Use unwrap() to crash if the other thread poisoned this lock.
            let shared_info = self.shared_info.read().unwrap();
            shared_info.state.clone()
        };
        let result = match instance_state {
            InstanceState::Starting | InstanceState::Running | InstanceState::Halting => {
                AsyncOutcome::Error("Guest Instance already running.".to_string())
            }
            _ => match self.start_instance() {
                Ok(_) => AsyncOutcome::Ok(0),
                Err(e) => {
                    let _ = self.stop();
                    AsyncOutcome::Error(format!("Cannot start microvm: {:?}", e))
                }
            },
        };
        // Using expect() to crash this thread as well if the other thread crashed.
        sender.send(result).expect("one-shot channel closed");
    }

    fn handle_stop_instance(&mut self, sender: AsyncOutcomeSender) {
        let result = match self.stop() {
            Ok(_) => AsyncOutcome::Ok(0),
            Err(e) => AsyncOutcome::Error(format!(
                "Errors detected during instance stop()! err: {:?}",
                e
            )),
        };
        sender.send(result).expect("one-shot channel closed");
    }

    fn is_instance_running(&self) -> bool {
        let instance_state = {
            // Use unwrap() to crash if the other thread poisoned this lock.
            let shared_info = self.shared_info.read().unwrap();
            shared_info.state.clone()
        };
        match instance_state {
            InstanceState::Uninitialized => false,
            _ => true,
        }
    }

    fn handle_put_drive(&mut self, drive_description: DriveDescription, sender: SyncOutcomeSender) {
        match self.put_block_device(BlockDeviceConfig::from(drive_description)) {
            Ok(ret) => sender
                .send(Box::new(ret))
                .map_err(|_| ())
                .expect("one-shot channel closed"),
            Err(e) => sender
                .send(Box::new(e))
                .map_err(|_| ())
                .expect("one-shot channel closed"),
        }
    }

    fn handle_put_logger(
        &mut self,
        logger_description: APILoggerDescription,
        sender: SyncOutcomeSender,
    ) {
        if self.is_instance_running() {
            sender
                .send(Box::new(SyncError::UpdateNotAllowedPostBoot))
                .map_err(|_| ())
                .expect("one-shot channel closed");
            return;
        }

        match api_logger_config::init_logger(logger_description) {
            Ok(_) => sender
                .send(Box::new(PutLoggerOutcome::Initialized))
                .map_err(|_| ())
                .expect("one-shot channel closed"),
            Err(e) => sender
                .send(Box::new(e))
                .map_err(|_| ())
                .expect("one-shot channel closed"),
        }
    }

    fn handle_put_boot_source(
        &mut self,
        boot_source_body: BootSourceBody,
        sender: SyncOutcomeSender,
    ) {
        if self.is_instance_running() {
            sender
                .send(Box::new(SyncError::UpdateNotAllowedPostBoot))
                .map_err(|_| ())
                .expect("one-shot channel closed");
            return;
        }

        let box_response: Box<GenerateResponse + Send> = match boot_source_body.local_image {
            // Check that the kernel path exists and it is valid.
            Some(image) => match File::open(image.kernel_image_path) {
                Ok(kernel_file) => {
                    let mut cmdline =
                        kernel_cmdline::Cmdline::new(x86_64::layout::CMDLINE_MAX_SIZE);
                    match cmdline.insert_str(
                        boot_source_body
                            .boot_args
                            .unwrap_or(String::from(DEFAULT_KERNEL_CMDLINE)),
                    ) {
                        Ok(_) => {
                            let kernel_config = KernelConfig {
                                kernel_file,
                                cmdline,
                                cmdline_addr: GuestAddress(x86_64::layout::CMDLINE_START),
                            };
                            // If the kernel was already configured, we have an update operation.
                            let outcome = match self.kernel_config {
                                Some(_) => PutBootSourceOutcome::Updated,
                                None => PutBootSourceOutcome::Created,
                            };
                            self.configure_kernel(kernel_config);
                            Box::new(outcome)
                        }
                        Err(_) => Box::new(PutBootSourceConfigError::InvalidKernelCommandLine),
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

    fn handle_get_machine_configuration(&self, sender: SyncOutcomeSender) {
        sender
            .send(Box::new(self.vm_config.clone()))
            .map_err(|_| ())
            .expect("one-shot channel closed");
    }

    fn handle_put_machine_configuration(
        &mut self,
        machine_config_body: MachineConfiguration,
        sender: SyncOutcomeSender,
    ) {
        if self.is_instance_running() {
            sender
                .send(Box::new(SyncError::UpdateNotAllowedPostBoot))
                .map_err(|_| ())
                .expect("one-shot channel closed");
            return;
        }

        let boxed_response = match self.put_virtual_machine_configuration(machine_config_body) {
            Ok(_) => Box::new(PutMachineConfigurationOutcome::Updated),
            Err(e) => Box::new(PutMachineConfigurationOutcome::Error(e)),
        };

        sender
            .send(boxed_response)
            .map_err(|_| ())
            .expect("one-shot channel closed");
    }

    fn handle_put_network_interface(
        &mut self,
        netif_body: NetworkInterfaceBody,
        sender: SyncOutcomeSender,
    ) {
        if self.is_instance_running() {
            sender
                .send(Box::new(SyncError::UpdateNotAllowedPostBoot))
                .map_err(|_| ())
                .expect("one-shot channel closed");
            return;
        }

        sender
            .send(Box::new(self.put_net_device(netif_body)))
            .map_err(|_| ())
            .expect("one-shot channel closed");
    }

    fn handle_rescan_block_device(&mut self, req_body: ActionBody, sender: SyncOutcomeSender) {
        if !self.is_instance_running() {
            sender
                .send(Box::new(SyncError::OperationNotAllowedPreBoot))
                .map_err(|_| ())
                .expect("one-shot channel closed");
            return;
        }

        sender
            .send(Box::new(self.rescan_block_device(req_body)))
            .map_err(|_| ())
            .expect("one-shot channel closed");
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
            ApiRequest::Async(req) => match req {
                AsyncRequest::StartInstance(sender) => self.handle_start_instance(sender),
                AsyncRequest::StopInstance(sender) => self.handle_stop_instance(sender),
            },
            ApiRequest::Sync(req) => match req {
                SyncRequest::GetMachineConfiguration(sender) => {
                    self.handle_get_machine_configuration(sender)
                }
                SyncRequest::PutBootSource(boot_source_body, sender) => {
                    self.handle_put_boot_source(boot_source_body, sender)
                }
                SyncRequest::PutDrive(drive_description, sender) => {
                    self.handle_put_drive(drive_description, sender)
                }
                SyncRequest::PutLogger(logger_description, sender) => {
                    self.handle_put_logger(logger_description, sender)
                }
                SyncRequest::PutMachineConfiguration(machine_config_body, sender) => {
                    self.handle_put_machine_configuration(machine_config_body, sender)
                }
                SyncRequest::PutNetworkInterface(netif_body, sender) => {
                    self.handle_put_network_interface(netif_body, sender)
                }
                SyncRequest::RescanBlockDevice(req_body, sender) => {
                    self.handle_rescan_block_device(req_body, sender)
                }
            },
        }

        Ok(())
    }

    #[cfg(test)]
    fn get_kernel_cmdline(&self) -> &str {
        if let Some(ref k) = self.kernel_config {
            k.cmdline.as_str()
        } else {
            ""
        }
    }
}

/// Starts a new vmm thread that can service API requests.
///
/// # Arguments
///
/// * `api_shared_info` - A parameter for storing information on the VMM (e.g the current state).
/// * `api_event_fd` - An event fd used for receiving API associated events.
/// * `from_api` - The receiver end point of the communication channel.
pub fn start_vmm_thread(
    api_shared_info: Arc<RwLock<InstanceInfo>>,
    api_event_fd: EventFd,
    from_api: Receiver<Box<ApiRequest>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        // If this fails, consider it fatal. Use expect().
        let mut vmm = Vmm::new(api_shared_info, api_event_fd, from_api).expect("cannot create VMM");
        let r = vmm.run_control(true);
        // Make sure we clean up when this loop breaks on error.
        if r.is_err() {
            // stop() is safe to call at any moment; ignore the result.
            let _ = vmm.stop();
        }
        // vmm thread errors are irrecoverable for now. Use expect().
        r.expect("VMM thread fail");
        // TODO: maybe offer through API: an instance status reporting error messages (r)
    })
}

#[cfg(test)]
mod tests {
    extern crate tempfile;

    use std::fs::File;

    use self::tempfile::NamedTempFile;

    use super::*;
    use api_server::request::sync::DeviceState;
    use data_model::vm::CpuFeaturesTemplate;
    use net_util::MacAddr;

    fn create_vmm_object() -> Vmm {
        let shared_info = Arc::new(RwLock::new(InstanceInfo {
            state: InstanceState::Uninitialized,
        }));

        let (_to_vmm, from_api) = channel();
        let vmm = Vmm::new(
            shared_info,
            EventFd::new().expect("cannot create eventFD"),
            from_api,
        ).expect("Cannot Create VMM");
        return vmm;
    }

    #[test]
    fn test_put_block_device() {
        let mut vmm = create_vmm_object();
        let f = NamedTempFile::new().unwrap();
        // Test that creating a new block device returns the correct output (i.e. "Created").
        let root_block_device = BlockDeviceConfig {
            drive_id: String::from("root"),
            path_on_host: f.path().to_path_buf(),
            is_root_device: true,
            partuuid: None,
            is_read_only: false,
            rate_limiter: None,
        };
        match vmm.put_block_device(root_block_device.clone()) {
            Ok(outcome) => assert!(outcome == PutDriveOutcome::Created),
            Err(_) => assert!(false),
        };
        assert!(
            vmm.block_device_configs
                .config_list
                .contains(&root_block_device)
        );

        // Test that creating a new block device returns the correct output (i.e. "Updated").
        let root_block_device = BlockDeviceConfig {
            drive_id: String::from("root"),
            path_on_host: f.path().to_path_buf(),
            is_root_device: true,
            partuuid: None,
            is_read_only: true,
            rate_limiter: None,
        };
        match vmm.put_block_device(root_block_device.clone()) {
            Ok(outcome) => assert!(outcome == PutDriveOutcome::Updated),
            Err(_) => assert!(false),
        };
        assert!(
            vmm.block_device_configs
                .config_list
                .contains(&root_block_device)
        );
    }

    #[test]
    fn test_put_net_device() {
        let mut vmm = create_vmm_object();

        // test create network interface
        let network_interface = NetworkInterfaceBody {
            iface_id: String::from("netif"),
            state: DeviceState::Attached,
            host_dev_name: String::from("hostname"),
            guest_mac: None,
            rx_rate_limiter: None,
            tx_rate_limiter: None,
        };
        match vmm.put_net_device(network_interface) {
            Ok(outcome) => assert!(outcome == SyncOkStatus::Created),
            Err(_) => assert!(false),
        }

        if let Ok(mac) = MacAddr::parse_str("01:23:45:67:89:0A") {
            // test update network interface
            let network_interface = NetworkInterfaceBody {
                iface_id: String::from("netif"),
                state: DeviceState::Attached,
                host_dev_name: String::from("hostname2"),
                guest_mac: Some(mac),
                rx_rate_limiter: None,
                tx_rate_limiter: None,
            };
            match vmm.put_net_device(network_interface) {
                Ok(outcome) => assert!(outcome == SyncOkStatus::Updated),
                Err(_) => assert!(false),
            }
        }
    }

    #[test]
    fn test_machine_configuration() {
        let mut vmm = create_vmm_object();

        // test the default values of machine config
        // vcpu_count = 1
        assert_eq!(vmm.vm_config.vcpu_count, Some(1));
        // mem_size = 128
        assert_eq!(vmm.vm_config.mem_size_mib, Some(128));
        // ht_enabled = false
        assert_eq!(vmm.vm_config.ht_enabled, Some(false));
        // no cpu template
        assert!(vmm.vm_config.cpu_template.is_none());

        // 1. Tests with no hyperthreading
        // test put machine configuration for vcpu count with valid value
        let machine_config = MachineConfiguration {
            vcpu_count: Some(3),
            mem_size_mib: None,
            ht_enabled: None,
            cpu_template: None,
        };
        assert!(
            vmm.put_virtual_machine_configuration(machine_config)
                .is_ok()
        );
        assert_eq!(vmm.vm_config.vcpu_count, Some(3));
        assert_eq!(vmm.vm_config.mem_size_mib, Some(128));
        assert_eq!(vmm.vm_config.ht_enabled, Some(false));

        // test put machine configuration for mem size with valid value
        let machine_config = MachineConfiguration {
            vcpu_count: None,
            mem_size_mib: Some(256),
            ht_enabled: None,
            cpu_template: None,
        };
        assert!(
            vmm.put_virtual_machine_configuration(machine_config)
                .is_ok()
        );
        assert_eq!(vmm.vm_config.vcpu_count, Some(3));
        assert_eq!(vmm.vm_config.mem_size_mib, Some(256));
        assert_eq!(vmm.vm_config.ht_enabled, Some(false));

        // Test Error cases for put_machine_configuration with invalid value for vcpu_count
        // Test that the put method return error & that the vcpu value is not changed
        let machine_config = MachineConfiguration {
            vcpu_count: Some(0),
            mem_size_mib: None,
            ht_enabled: None,
            cpu_template: None,
        };
        assert_eq!(
            vmm.put_virtual_machine_configuration(machine_config)
                .unwrap_err(),
            PutMachineConfigurationError::InvalidVcpuCount
        );
        assert_eq!(vmm.vm_config.vcpu_count, Some(3));

        // Test Error cases for put_machine_configuration with invalid value for the mem_size_mib
        // Test that the put method return error & that the mem_size_mib value is not changed
        let machine_config = MachineConfiguration {
            vcpu_count: Some(1),
            mem_size_mib: Some(0),
            ht_enabled: Some(false),
            cpu_template: Some(CpuFeaturesTemplate::T2),
        };
        assert_eq!(
            vmm.put_virtual_machine_configuration(machine_config)
                .unwrap_err(),
            PutMachineConfigurationError::InvalidMemorySize
        );
        assert_eq!(vmm.vm_config.vcpu_count, Some(3));
        assert_eq!(vmm.vm_config.mem_size_mib, Some(256));
        assert_eq!(vmm.vm_config.ht_enabled, Some(false));
        assert!(vmm.vm_config.cpu_template.is_none());

        // 2. Test with hyperthreading enabled
        // Test that you can't change the hyperthreading value to false when the vcpu count
        // is odd
        let machine_config = MachineConfiguration {
            vcpu_count: None,
            mem_size_mib: None,
            ht_enabled: Some(true),
            cpu_template: None,
        };
        assert_eq!(
            vmm.put_virtual_machine_configuration(machine_config)
                .unwrap_err(),
            PutMachineConfigurationError::InvalidVcpuCount
        );
        assert_eq!(vmm.vm_config.ht_enabled, Some(false));
        // Test that you can change the ht flag when you have a valid vcpu count
        // Also set the CPU Template since we are here
        let machine_config = MachineConfiguration {
            vcpu_count: Some(2),
            mem_size_mib: None,
            ht_enabled: Some(true),
            cpu_template: Some(CpuFeaturesTemplate::T2),
        };
        assert!(
            vmm.put_virtual_machine_configuration(machine_config)
                .is_ok()
        );
        assert_eq!(vmm.vm_config.vcpu_count, Some(2));
        assert_eq!(vmm.vm_config.ht_enabled, Some(true));
        assert_eq!(vmm.vm_config.cpu_template, Some(CpuFeaturesTemplate::T2));
    }

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
        assert!(epev.fd.write(1).is_ok());

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
        assert!(epev.fd.write(1).is_ok());

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
        assert!(epev.fd.write(1).is_ok());

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

    #[test]
    fn test_kvm_context() {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::io::FromRawFd;

        let c = KvmContext::new().unwrap();
        let nr_vcpus = c.nr_vcpus();
        let max_vcpus = c.max_vcpus();

        assert!(nr_vcpus > 0);
        assert!(max_vcpus >= nr_vcpus);

        let kvm = Kvm::new().unwrap();
        let f = unsafe { File::from_raw_fd(kvm.as_raw_fd()) };
        let m1 = f.metadata().unwrap();
        let m2 = File::open("/dev/kvm").unwrap().metadata().unwrap();

        assert_eq!(m1.dev(), m2.dev());
        assert_eq!(m1.ino(), m2.ino());
    }

    #[test]
    pub fn test_attach_block_devices() {
        let mut vmm = create_vmm_object();
        let block_file = NamedTempFile::new().unwrap();
        let kernel_file_temp =
            NamedTempFile::new().expect("Failed to create temporary kernel file.");
        let kernel_path = String::from(kernel_file_temp.path().to_path_buf().to_str().unwrap());
        let kernel_file = File::open(kernel_path).unwrap();

        // Use Case 1: Root Block Device is not specified through PARTUUID.
        let root_block_device = BlockDeviceConfig {
            drive_id: String::from("root"),
            path_on_host: block_file.path().to_path_buf(),
            is_root_device: true,
            partuuid: None,
            is_read_only: false,
            rate_limiter: None,
        };
        // Test that creating a new block device returns the correct output.
        match vmm.put_block_device(root_block_device.clone()) {
            Ok(outcome) => assert!(outcome == PutDriveOutcome::Created),
            Err(_) => assert!(false),
        };
        assert!(vmm.init_guest_memory().is_ok());
        assert!(vmm.guest_memory.is_some());
        let mut cmdline = kernel_cmdline::Cmdline::new(x86_64::layout::CMDLINE_MAX_SIZE);
        assert!(cmdline.insert_str(DEFAULT_KERNEL_CMDLINE).is_ok());
        let kernel_cfg = KernelConfig {
            cmdline,
            kernel_file,
            cmdline_addr: GuestAddress(x86_64::layout::CMDLINE_START),
        };
        vmm.configure_kernel(kernel_cfg);
        let guest_mem = vmm.guest_memory.clone().unwrap();
        let mut device_manager =
            MMIODeviceManager::new(guest_mem.clone(), x86_64::get_32bit_gap_start() as u64);
        assert!(vmm.attach_block_devices(&mut device_manager).is_ok());
        assert!(vmm.get_kernel_cmdline().contains("root=/dev/vda"));

        // Use Case 2: Root Block Device is specified through PARTUUID.
        let mut vmm = create_vmm_object();
        let root_block_device = BlockDeviceConfig {
            drive_id: String::from("root"),
            path_on_host: block_file.path().to_path_buf(),
            is_root_device: true,
            partuuid: Some("0eaa91a0-01".to_string()),
            is_read_only: false,
            rate_limiter: None,
        };
        let kernel_file_temp =
            NamedTempFile::new().expect("Failed to create temporary kernel file.");
        let kernel_path = String::from(kernel_file_temp.path().to_path_buf().to_str().unwrap());
        let kernel_file = File::open(kernel_path).unwrap();

        // Test that creating a new block device returns the correct output.
        match vmm.put_block_device(root_block_device.clone()) {
            Ok(outcome) => assert!(outcome == PutDriveOutcome::Created),
            Err(_) => assert!(false),
        };
        assert!(vmm.init_guest_memory().is_ok());
        assert!(vmm.guest_memory.is_some());
        let mut cmdline = kernel_cmdline::Cmdline::new(x86_64::layout::CMDLINE_MAX_SIZE);
        assert!(cmdline.insert_str(DEFAULT_KERNEL_CMDLINE).is_ok());
        let kernel_cfg = KernelConfig {
            cmdline,
            kernel_file,
            cmdline_addr: GuestAddress(x86_64::layout::CMDLINE_START),
        };
        vmm.configure_kernel(kernel_cfg);
        let guest_mem = vmm.guest_memory.clone().unwrap();
        let mut device_manager =
            MMIODeviceManager::new(guest_mem.clone(), x86_64::get_32bit_gap_start() as u64);
        assert!(vmm.attach_block_devices(&mut device_manager).is_ok());
        assert!(
            vmm.get_kernel_cmdline()
                .contains("root=PARTUUID=0eaa91a0-01")
        );

        // Use Case 3: Root Block Device is not added at all.
        let mut vmm = create_vmm_object();
        let non_root_block_device = BlockDeviceConfig {
            drive_id: String::from("not_root"),
            path_on_host: block_file.path().to_path_buf(),
            is_root_device: false,
            partuuid: Some("0eaa91a0-01".to_string()),
            is_read_only: false,
            rate_limiter: None,
        };
        let kernel_file_temp =
            NamedTempFile::new().expect("Failed to create temporary kernel file.");
        let kernel_path = String::from(kernel_file_temp.path().to_path_buf().to_str().unwrap());
        let kernel_file = File::open(kernel_path).unwrap();

        // Test that creating a new block device returns the correct output.
        match vmm.put_block_device(non_root_block_device.clone()) {
            Ok(outcome) => assert!(outcome == PutDriveOutcome::Created),
            Err(_) => assert!(false),
        };
        assert!(vmm.init_guest_memory().is_ok());
        assert!(vmm.guest_memory.is_some());
        let mut cmdline = kernel_cmdline::Cmdline::new(x86_64::layout::CMDLINE_MAX_SIZE);
        assert!(cmdline.insert_str(DEFAULT_KERNEL_CMDLINE).is_ok());
        let kernel_cfg = KernelConfig {
            cmdline,
            kernel_file,
            cmdline_addr: GuestAddress(x86_64::layout::CMDLINE_START),
        };
        vmm.configure_kernel(kernel_cfg);
        let guest_mem = vmm.guest_memory.clone().unwrap();
        let mut device_manager =
            MMIODeviceManager::new(guest_mem.clone(), x86_64::get_32bit_gap_start() as u64);
        assert!(vmm.attach_block_devices(&mut device_manager).is_ok());
        // Test that kernel commandline does not contain either /dev/vda or PARTUUID.
        assert!(!vmm.get_kernel_cmdline().contains("root=PARTUUID="));
        assert!(!vmm.get_kernel_cmdline().contains("root=/dev/vda"));

        // Test that the non root device is attached.
        assert!(
            device_manager
                .get_address(&non_root_block_device.drive_id)
                .is_some()
        );
    }
}

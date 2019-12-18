// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use timerfd::{ClockId, SetTimeFlags, TimerFd, TimerState};

use std::fs::{File, OpenOptions};
use std::path::PathBuf;
use std::process;
use std::time::Duration;

use super::{
    serde_json, EpollContext, EpollDispatch, EventLoopExitReason, KvmContext, MMIODeviceManager,
    PortIODeviceManager, Vcpu, VcpuConfig, Vm, Vmm, VmmConfig, FC_EXIT_CODE_INVALID_JSON,
};

use arch::DeviceType;
use device_manager::mmio::MMIO_CFG_SPACE_OFF;
use devices::virtio::vsock::{TYPE_VSOCK, VSOCK_EVENTS_COUNT};
use devices::virtio::{
    self, MmioDevice, BLOCK_EVENTS_COUNT, NET_EVENTS_COUNT, TYPE_BLOCK, TYPE_NET,
};
use error::*;

use kernel::{cmdline as kernel_cmdline, loader as kernel_loader};
use logger::{Metric, LOGGER, METRICS};
use memory_model::{GuestAddress, GuestMemory};
use polly::event_manager::EventManager;
use utils::time::TimestampUs;
use vmm_config;
use vmm_config::boot_source::{BootSourceConfig, KernelConfig, DEFAULT_KERNEL_CMDLINE};
use vmm_config::device_config::DeviceConfigs;
use vmm_config::drive::{BlockDeviceConfig, BlockDeviceConfigs, DriveError};
use vmm_config::instance_info::InstanceInfo;
use vmm_config::logger::{LoggerConfig, LoggerConfigError, LoggerLevel, LoggerWriter};
use vmm_config::machine_config::{VmConfig, VmConfigError};
use vmm_config::net::{
    NetworkInterfaceConfig, NetworkInterfaceConfigs, NetworkInterfaceError,
    NetworkInterfaceUpdateConfig,
};
use vmm_config::vsock::{VsockDeviceConfig, VsockError};

const WRITE_METRICS_PERIOD_SECONDS: u64 = 60;

/// Enables pre-boot setup, instantiation and real time configuration of a Firecracker VMM.
pub struct VmmBuilder {
    device_configs: DeviceConfigs,
    //    epoll_context: EpollContext,
    kernel_config: Option<KernelConfig>,
    vm_config: VmConfig,
    //    shared_info: Arc<RwLock<InstanceInfo>>,
    seccomp_level: u32,
}

impl VmmBuilder {
    /// Creates a new `VmmBuilder`.
    pub fn new(seccomp_level: u32) -> Result<Self> {
        let device_configs = DeviceConfigs::new(
            BlockDeviceConfigs::new(),
            NetworkInterfaceConfigs::new(),
            None,
        );

        Ok(VmmBuilder {
            device_configs,
            kernel_config: None,
            vm_config: VmConfig::default(),
            seccomp_level,
        })
    }

    /// Configures Vmm resources as described by the `config_json` param.
    pub fn from_json(
        config_json: &String,
        seccomp_level: u32,
        firecracker_version: String,
    ) -> std::result::Result<Self, VmmActionError> {
        let mut builder: Self = Self::new(seccomp_level).expect("Cannot create VmmBuilder");
        let vmm_config: VmmConfig = serde_json::from_slice::<VmmConfig>(config_json.as_bytes())
            .unwrap_or_else(|e| {
                error!("Invalid json: {}", e);
                process::exit(i32::from(FC_EXIT_CODE_INVALID_JSON));
            });

        if let Some(logger) = vmm_config.logger {
            vmm_config::logger::init_logger(logger, firecracker_version)
                .map_err(|e| VmmActionError::Logger(ErrorKind::User, e))?;
        }
        if let Some(machine_config) = vmm_config.machine_config {
            builder.with_vm_config(machine_config)?;
        }
        builder.with_boot_source(vmm_config.boot_source)?;
        for drive_config in vmm_config.block_devices.into_iter() {
            builder.with_block_device(drive_config)?;
        }
        for net_config in vmm_config.net_devices.into_iter() {
            builder.with_net_device(net_config)?;
        }
        if let Some(vsock_config) = vmm_config.vsock_device {
            builder.with_vsock_device(vsock_config)?;
        }
        Ok(builder)
    }

    /// Returns the VmConfig.
    pub fn vm_config(&self) -> &VmConfig {
        &self.vm_config
    }

    /// Set the machine configuration of the microVM.
    pub fn with_vm_config(&mut self, machine_config: VmConfig) -> UserResult {
        if machine_config.vcpu_count == Some(0) {
            return Err(VmConfigError::InvalidVcpuCount.into());
        }

        if machine_config.mem_size_mib == Some(0) {
            return Err(VmConfigError::InvalidMemorySize.into());
        }

        let ht_enabled = machine_config
            .ht_enabled
            .unwrap_or_else(|| self.vm_config.ht_enabled.unwrap());

        let vcpu_count_value = machine_config
            .vcpu_count
            .unwrap_or_else(|| self.vm_config.vcpu_count.unwrap());

        // If hyperthreading is enabled or is to be enabled in this call
        // only allow vcpu count to be 1 or even.
        if ht_enabled && vcpu_count_value > 1 && vcpu_count_value % 2 == 1 {
            return Err(VmConfigError::InvalidVcpuCount.into());
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

    fn with_kernel_config(&mut self, kernel_config: KernelConfig) {
        self.kernel_config = Some(kernel_config);
    }

    /// Set the guest boot source configuration.
    pub fn with_boot_source(&mut self, boot_source_cfg: BootSourceConfig) -> UserResult {
        use BootSourceConfigError::{
            InvalidKernelCommandLine, InvalidKernelPath, UpdateNotAllowedPostBoot,
        };
        use ErrorKind::User;
        use VmmActionError::BootSource;

        let kernel_file = File::open(boot_source_cfg.kernel_image_path)
            .map_err(|e| BootSource(User, InvalidKernelPath(e)))?;

        let mut cmdline = kernel_cmdline::Cmdline::new(arch::CMDLINE_MAX_SIZE);
        cmdline
            .insert_str(
                boot_source_cfg
                    .boot_args
                    .unwrap_or_else(|| String::from(DEFAULT_KERNEL_CMDLINE)),
            )
            .map_err(|e| BootSource(User, InvalidKernelCommandLine(e.to_string())))?;

        let kernel_config = KernelConfig {
            kernel_file,
            cmdline,
        };
        self.with_kernel_config(kernel_config);

        Ok(())
    }

    /// Inserts a block to be attached when the VM starts.
    // Only call this function as part of user configuration.
    // If the drive_id does not exist, a new Block Device Config is added to the list.
    pub fn with_block_device(&mut self, block_device_config: BlockDeviceConfig) -> UserResult {
        self.device_configs
            .block
            .insert(block_device_config)
            .map_err(VmmActionError::from)
    }

    /// Updates the path of the host file backing the emulated block device with id `drive_id`.
    pub fn update_block_device_path(
        &mut self,
        drive_id: String,
        path_on_host: String,
    ) -> UserResult {
        // Get the block device configuration specified by drive_id.
        let block_device_index = self
            .device_configs
            .block
            .get_index_of_drive_id(&drive_id)
            .ok_or(DriveError::InvalidBlockDeviceID)?;

        let file_path = PathBuf::from(path_on_host);
        // Try to open the file specified by path_on_host using the permissions of the block_device.
        let _ = OpenOptions::new()
            .read(true)
            .write(!self.device_configs.block.config_list[block_device_index].is_read_only())
            .open(&file_path)
            .map_err(|_| DriveError::CannotOpenBlockDevice)?;

        // Update the path of the block device with the specified path_on_host.
        self.device_configs.block.config_list[block_device_index].path_on_host = file_path;

        Ok(())
    }

    /// Inserts a network device to be attached when the VM starts.
    pub fn with_net_device(&mut self, body: NetworkInterfaceConfig) -> UserResult {
        self.device_configs
            .network_interface
            .insert(body)
            .map_err(|e| VmmActionError::NetworkConfig(ErrorKind::User, e))
    }

    /// Updates configuration for an emulated net device as described in `new_cfg`.
    pub fn update_net_rate_limiters(
        &mut self,
        new_cfg: NetworkInterfaceUpdateConfig,
    ) -> UserResult {
        let old_cfg = self
            .device_configs
            .network_interface
            .iter_mut()
            .find(|&&mut ref c| c.iface_id == new_cfg.iface_id)
            .ok_or(NetworkInterfaceError::DeviceIdNotFound)?;

        macro_rules! update_rate_limiter {
            ($rate_limiter: ident) => {{
                if let Some(new_rlim_cfg) = new_cfg.$rate_limiter {
                    if let Some(ref mut old_rlim_cfg) = old_cfg.$rate_limiter {
                        // We already have an RX rate limiter set, so we'll update it.
                        old_rlim_cfg.update(&new_rlim_cfg);
                    } else {
                        // No old RX rate limiter; create one now.
                        old_cfg.$rate_limiter = Some(new_rlim_cfg);
                    }
                }
            }};
        }

        update_rate_limiter!(rx_rate_limiter);
        update_rate_limiter!(tx_rate_limiter);
        Ok(())
    }

    /// Sets a vsock device to be attached when the VM starts.
    pub fn with_vsock_device(&mut self, config: VsockDeviceConfig) -> UserResult {
        self.device_configs.vsock = Some(config);
        Ok(())
    }

    /// Builds and starts a microVM based on the current configuration.
    pub fn build_microvm(
        mut self,
        epoll_context: &mut EpollContext,
    ) -> std::result::Result<Vmm, VmmActionError> {
        let guest_memory = self.create_guest_memory()?;
        let kernel_entry_addr = self.load_kernel(&guest_memory)?;

        let kernel_config = self
            .kernel_config
            .take()
            .ok_or(StartMicrovmError::MissingKernelConfig)?;

        // The unwraps are ok to use because the values are initialized using defaults if not
        // supplied by the user.
        let vcpu_config = VcpuConfig {
            vcpu_count: self.vm_config.vcpu_count.unwrap(),
            ht_enabled: self.vm_config.ht_enabled.unwrap(),
            cpu_template: self.vm_config.cpu_template,
        };

        let builder_config = VmmBuilderzConfig {
            guest_memory,
            entry_addr: kernel_entry_addr,
            kernel_cmdline: kernel_config.cmdline,
            vcpu_config,
            seccomp_level: self.seccomp_level,
        };

        let mut builder = VmmBuilderz::new(epoll_context, builder_config)?;

        self.attach_block_devices(&mut builder, epoll_context)?;
        self.attach_net_devices(&mut builder, epoll_context)?;
        self.attach_vsock_device(&mut builder, epoll_context)?;

        builder.run(epoll_context)
    }

    fn create_guest_memory(&self) -> std::result::Result<GuestMemory, StartMicrovmError> {
        let mem_size = self
            .vm_config
            .mem_size_mib
            .ok_or(StartMicrovmError::GuestMemory(
                memory_model::GuestMemoryError::MemoryNotInitialized,
            ))?
            << 20;
        let arch_mem_regions = arch::arch_memory_regions(mem_size);

        Ok(GuestMemory::new(&arch_mem_regions).map_err(StartMicrovmError::GuestMemory)?)
    }

    fn load_kernel(
        &mut self,
        guest_memory: &GuestMemory,
    ) -> std::result::Result<GuestAddress, StartMicrovmError> {
        use StartMicrovmError::*;

        // This is the easy way out of consuming the value of the kernel_cmdline.
        let kernel_config = self.kernel_config.as_mut().ok_or(MissingKernelConfig)?;

        let entry_addr = kernel_loader::load_kernel(
            guest_memory,
            &mut kernel_config.kernel_file,
            arch::get_kernel_start(),
        )
        .map_err(KernelLoader)?;

        Ok(entry_addr)
    }

    fn attach_block_devices(
        &mut self,
        builder: &mut VmmBuilderz,
        epoll_context: &mut EpollContext,
    ) -> std::result::Result<(), StartMicrovmError> {
        use StartMicrovmError::*;

        // If no PARTUUID was specified for the root device, try with the /dev/vda.
        if self.device_configs.block.has_root_block_device()
            && !self.device_configs.block.has_partuuid_root()
        {
            let kernel_cmdline = builder.kernel_cmdline_mut();

            kernel_cmdline.insert_str("root=/dev/vda")?;

            let flags = if self.device_configs.block.has_read_only_root() {
                "ro"
            } else {
                "rw"
            };

            kernel_cmdline.insert_str(flags)?;
        }

        for drive_config in self.device_configs.block.config_list.iter_mut() {
            // Add the block device from file.
            let block_file = OpenOptions::new()
                .read(true)
                .write(!drive_config.is_read_only)
                .open(&drive_config.path_on_host)
                .map_err(OpenBlockDevice)?;

            if drive_config.is_root_device && drive_config.get_partuuid().is_some() {
                let kernel_cmdline = builder.kernel_cmdline_mut();

                kernel_cmdline.insert_str(format!(
                    "root=PARTUUID={}",
                    //The unwrap is safe as we are firstly checking that partuuid is_some().
                    drive_config.get_partuuid().unwrap()
                ))?;

                let flags = if drive_config.is_read_only() {
                    "ro"
                } else {
                    "rw"
                };

                kernel_cmdline.insert_str(flags)?;
            }

            let epoll_config = epoll_context.allocate_tokens_for_virtio_device(
                TYPE_BLOCK,
                &drive_config.drive_id,
                BLOCK_EVENTS_COUNT,
            );

            let rate_limiter = drive_config
                .rate_limiter
                .map(vmm_config::RateLimiterConfig::into_rate_limiter)
                .transpose()
                .map_err(CreateRateLimiter)?;

            let block_box = Box::new(
                devices::virtio::Block::new(
                    block_file,
                    drive_config.is_read_only,
                    epoll_config,
                    rate_limiter,
                )
                .map_err(CreateBlockDevice)?,
            );

            builder.attach_device(
                drive_config.drive_id.clone(),
                MmioDevice::new(builder.guest_memory().clone(), block_box).map_err(|e| {
                    RegisterMMIODevice(super::device_manager::mmio::Error::CreateMmioDevice(e))
                })?,
            )?;
        }

        Ok(())
    }

    fn attach_net_devices(
        &mut self,
        builder: &mut VmmBuilderz,
        epoll_context: &mut EpollContext,
    ) -> UserResult {
        use StartMicrovmError::*;

        for cfg in self.device_configs.network_interface.iter_mut() {
            let epoll_config = epoll_context.allocate_tokens_for_virtio_device(
                TYPE_NET,
                &cfg.iface_id,
                NET_EVENTS_COUNT,
            );

            let allow_mmds_requests = cfg.allow_mmds_requests();

            let rx_rate_limiter = cfg
                .rx_rate_limiter
                .map(vmm_config::RateLimiterConfig::into_rate_limiter)
                .transpose()
                .map_err(CreateRateLimiter)?;

            let tx_rate_limiter = cfg
                .tx_rate_limiter
                .map(vmm_config::RateLimiterConfig::into_rate_limiter)
                .transpose()
                .map_err(CreateRateLimiter)?;

            let tap = cfg.open_tap().map_err(|_| NetDeviceNotConfigured)?;

            let net_box = Box::new(
                devices::virtio::Net::new_with_tap(
                    tap,
                    cfg.guest_mac(),
                    epoll_config,
                    rx_rate_limiter,
                    tx_rate_limiter,
                    allow_mmds_requests,
                )
                .map_err(CreateNetDevice)?,
            );

            builder.attach_device(
                cfg.iface_id.clone(),
                MmioDevice::new(builder.guest_memory().clone(), net_box).map_err(|e| {
                    RegisterMMIODevice(super::device_manager::mmio::Error::CreateMmioDevice(e))
                })?,
            )?;
        }

        Ok(())
    }

    fn attach_vsock_device(
        &mut self,
        builder: &mut VmmBuilderz,
        epoll_context: &mut EpollContext,
    ) -> UserResult {
        if let Some(cfg) = &self.device_configs.vsock {
            let backend = devices::virtio::vsock::VsockUnixBackend::new(
                u64::from(cfg.guest_cid),
                cfg.uds_path.clone(),
            )
            .map_err(StartMicrovmError::CreateVsockBackend)?;

            let epoll_config = epoll_context.allocate_tokens_for_virtio_device(
                TYPE_VSOCK,
                &cfg.vsock_id,
                VSOCK_EVENTS_COUNT,
            );

            let vsock_box = Box::new(
                devices::virtio::Vsock::new(u64::from(cfg.guest_cid), epoll_config, backend)
                    .map_err(StartMicrovmError::CreateVsockDevice)?,
            );

            builder.attach_device(
                cfg.vsock_id.clone(),
                MmioDevice::new(builder.guest_memory().clone(), vsock_box).map_err(|e| {
                    StartMicrovmError::RegisterMMIODevice(
                        super::device_manager::mmio::Error::CreateMmioDevice(e),
                    )
                })?,
            )?;
        }

        Ok(())
    }
}

/// Encapsulates configuration parameters for a `VmmBuilderz`.
pub struct VmmBuilderzConfig {
    /// The guest memory object for this VM.
    pub guest_memory: GuestMemory,
    /// The guest physical address of the execution entry point.
    pub entry_addr: GuestAddress,
    /// Base kernel command line contents.
    pub kernel_cmdline: kernel_cmdline::Cmdline,
    /// vCPU configuration paramters.
    pub vcpu_config: VcpuConfig,
    /// Seccomp filtering level.
    pub seccomp_level: u32,
}

/// Helps build a Vmm.
pub struct VmmBuilderz {
    vmm: Vmm,
    vcpus: Vec<Vcpu>,
}

impl VmmBuilderz {
    /// Create a new VmmBuilderz.
    pub fn new(
        epoll_context: &mut EpollContext,
        config: VmmBuilderzConfig,
    ) -> std::result::Result<Self, VmmActionError> {
        let write_metrics_event_fd = TimerFd::new_custom(ClockId::Monotonic, true, true)
            .map_err(Error::TimerFd)
            .map_err(StartMicrovmError::Internal)?;

        let event_manager = EventManager::new()
            .map_err(Error::EventManager)
            .map_err(StartMicrovmError::Internal)?;

        epoll_context
            .add_epollin_event(&event_manager, EpollDispatch::PollyEvent)
            .expect("Cannot cascade EventManager from epoll_context");

        epoll_context
            .add_epollin_event(
                // non-blocking & close on exec
                &write_metrics_event_fd,
                EpollDispatch::WriteMetrics,
            )
            .expect("Cannot add write metrics TimerFd to epoll.");

        let kvm = KvmContext::new()
            .map_err(Error::KvmContext)
            .map_err(StartMicrovmError::Internal)?;

        let mut vm = Vm::new(kvm.fd())
            .map_err(Error::Vm)
            .map_err(StartMicrovmError::Internal)?;

        vm.memory_init(config.guest_memory.clone(), &kvm)
            .map_err(StartMicrovmError::ConfigureVm)?;

        // Instantiate the MMIO device manager.
        // 'mmio_base' address has to be an address which is protected by the kernel
        // and is architectural specific.
        let mmio_device_manager = MMIODeviceManager::new(
            config.guest_memory.clone(),
            &mut (arch::MMIO_MEM_START as u64),
            (arch::IRQ_BASE, arch::IRQ_MAX),
        );

        let mut vmm = Vmm {
            stdin_handle: std::io::stdin(),
            guest_memory: config.guest_memory,
            vcpu_config: config.vcpu_config,
            kernel_cmdline: config.kernel_cmdline,
            vcpus_handles: Vec::new(),
            exit_evt: None,
            vm,
            mmio_device_manager,
            #[cfg(target_arch = "x86_64")]
            pio_device_manager: PortIODeviceManager::new()
                .map_err(Error::CreateLegacyDevice)
                .map_err(StartMicrovmError::Internal)?,
            write_metrics_event_fd,
            seccomp_level: config.seccomp_level,
            event_manager,
        };

        // For x86_64 we need to create the interrupt controller before calling `KVM_CREATE_VCPUS`
        // while on aarch64 we need to do it the other way around.
        #[cfg(target_arch = "x86_64")]
        {
            vmm.setup_interrupt_controller()?;
            // This call has to be here after setting up the irqchip, because
            // we set up some irqfd inside for some reason.
            vmm.attach_legacy_devices()?;
        }

        // This was supposed to be the timestamp when the start command is recevied. Having this
        // here just to create the vcpu; going forward the req timestamp will prob be somehow
        // decoupled from the creation. At this point it's still fine because we create the
        // builder and run the Vmm when the StartMicrovm request is received by the controller.
        let request_ts = TimestampUs::default();
        let vcpus = vmm.create_vcpus(config.entry_addr, request_ts)?;

        #[cfg(target_arch = "aarch64")]
        {
            vmm.setup_interrupt_controller()?;
            vmm.attach_legacy_devices()?;
        }

        Ok(VmmBuilderz { vmm, vcpus })
    }

    /// Return a reference to the guest memory object used by the builder.
    pub fn guest_memory(&self) -> &GuestMemory {
        self.vmm.guest_memory()
    }

    /// Returns a mutable reference to the guest kernel cmdline.
    pub fn kernel_cmdline_mut(&mut self) -> &mut kernel_cmdline::Cmdline {
        &mut self.vmm.kernel_cmdline
    }

    /// Adds a MmioDevice.
    pub fn attach_device(
        &mut self,
        id: String,
        device: MmioDevice,
    ) -> std::result::Result<(), StartMicrovmError> {
        // TODO: we currently map into StartMicrovmError::RegisterBlockDevice for all
        // devices at the end of device_manager.register_mmio_device.
        let type_id = device.device().device_type();
        let cmdline = &mut self.vmm.kernel_cmdline;

        self.vmm
            .mmio_device_manager
            .register_mmio_device(self.vmm.vm.fd(), device, cmdline, type_id, id.as_str())
            .map_err(StartMicrovmError::RegisterBlockDevice)?;

        Ok(())
    }

    /// Start running and return the Vmm.
    pub fn run(
        mut self,
        epoll_context: &mut EpollContext,
    ) -> std::result::Result<Vmm, VmmActionError> {
        // Write the kernel command line to guest memory. This is x86_64 specific, since on
        // aarch64 the command line will be specified through the FDT.
        #[cfg(target_arch = "x86_64")]
        kernel_loader::load_cmdline(
            self.vmm.guest_memory(),
            GuestAddress(arch::x86_64::layout::CMDLINE_START),
            &self
                .vmm
                .kernel_cmdline
                .as_cstring()
                .map_err(StartMicrovmError::LoadCommandline)?,
        )
        .map_err(StartMicrovmError::LoadCommandline)?;

        self.vmm.configure_system(self.vcpus.as_slice())?;

        self.vmm.register_events(epoll_context)?;

        self.vmm.start_vcpus(self.vcpus)?;

        // Arm the log write timer.
        // TODO: the timer does not stop on InstanceStop.
        let timer_state = TimerState::Periodic {
            current: Duration::from_secs(WRITE_METRICS_PERIOD_SECONDS),
            interval: Duration::from_secs(WRITE_METRICS_PERIOD_SECONDS),
        };
        self.vmm
            .write_metrics_event_fd
            .set_state(timer_state, SetTimeFlags::Default);

        // Log the metrics straight away to check the process startup time.
        if LOGGER.log_metrics().is_err() {
            METRICS.logger.missed_metrics_count.inc();
        }

        Ok(self.vmm)
    }
}

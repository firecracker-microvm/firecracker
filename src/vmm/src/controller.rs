use std::convert::TryInto;
use std::fs::{File, OpenOptions};
use std::io;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::process;
use std::result;
use std::sync::{Arc, RwLock};

use super::{
    EpollContext, EpollDispatch, ErrorKind, EventLoopExitReason, Result, UserResult, VcpuConfig,
    Vmm, VmmActionError, VmmBuilder, VmmBuilderConfig, VmmConfig, FC_EXIT_CODE_INVALID_JSON,
};

use arch::DeviceType;
use arch::InitrdConfig;
use device_manager::mmio::MMIO_CFG_SPACE_OFF;
use devices::virtio::vsock::{TYPE_VSOCK, VSOCK_EVENTS_COUNT};
use devices::virtio::{
    self, MmioDevice, BLOCK_EVENTS_COUNT, NET_EVENTS_COUNT, TYPE_BLOCK, TYPE_NET,
};
use error::{LoadInitrdError, StartMicrovmError};
use kernel::{cmdline as kernel_cmdline, loader as kernel_loader};
use logger::error::LoggerError;
use logger::LOGGER;
use seccomp::BpfProgram;
use utils::eventfd::EventFd;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};
use vmm_config;
use vmm_config::boot_source::{BootSourceConfig, KernelConfig, DEFAULT_KERNEL_CMDLINE};
use vmm_config::device_config::DeviceConfigs;
use vmm_config::drive::{BlockDeviceConfig, BlockDeviceConfigs, DriveError};
use vmm_config::instance_info::InstanceInfo;
use vmm_config::logger::LoggerConfigError;
use vmm_config::machine_config::{VmConfig, VmConfigError};
use vmm_config::net::{
    NetworkInterfaceConfig, NetworkInterfaceConfigs, NetworkInterfaceError,
    NetworkInterfaceUpdateConfig,
};
use vmm_config::vsock::{VsockDeviceConfig, VsockError};

/// Enables pre-boot setup, instantiation and real time configuration of a Firecracker VMM.
pub struct VmmController {
    device_configs: DeviceConfigs,
    epoll_context: EpollContext,
    kernel_config: Option<KernelConfig>,
    vm_config: VmConfig,
    shared_info: Arc<RwLock<InstanceInfo>>,
    vmm: Option<Vmm>,
}

impl VmmController {
    fn is_instance_initialized(&self) -> bool {
        self.shared_info
            .read()
            .expect("poisoned shared_info")
            .started
    }

    /// Inserts a block to be attached when the VM starts.
    // Only call this function as part of user configuration.
    // If the drive_id does not exist, a new Block Device Config is added to the list.
    pub fn insert_block_device(&mut self, block_device_config: BlockDeviceConfig) -> UserResult {
        if self.is_instance_initialized() {
            return Err(DriveError::UpdateNotAllowedPostBoot.into());
        }
        self.device_configs
            .block
            .insert(block_device_config)
            .map_err(VmmActionError::from)
    }

    /// Inserts a network device to be attached when the VM starts.
    pub fn insert_net_device(&mut self, body: NetworkInterfaceConfig) -> UserResult {
        if self.is_instance_initialized() {
            return Err(NetworkInterfaceError::UpdateNotAllowedPostBoot.into());
        }
        self.device_configs
            .network_interface
            .insert(body)
            .map_err(|e| VmmActionError::NetworkConfig(ErrorKind::User, e))
    }

    /// Sets a vsock device to be attached when the VM starts.
    pub fn set_vsock_device(&mut self, config: VsockDeviceConfig) -> UserResult {
        if self.is_instance_initialized() {
            Err(VmmActionError::VsockConfig(
                ErrorKind::User,
                VsockError::UpdateNotAllowedPostBoot,
            ))
        } else {
            self.device_configs.vsock = Some(config);
            Ok(())
        }
    }

    fn attach_block_devices(
        &mut self,
        builder: &mut VmmBuilder,
    ) -> result::Result<(), StartMicrovmError> {
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

            let epoll_config = self.epoll_context.allocate_tokens_for_virtio_device(
                TYPE_BLOCK,
                &drive_config.drive_id,
                BLOCK_EVENTS_COUNT,
            );

            let rate_limiter = drive_config
                .rate_limiter
                .map(vmm_config::RateLimiterConfig::try_into)
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
        builder: &mut VmmBuilder,
    ) -> result::Result<(), StartMicrovmError> {
        use StartMicrovmError::*;

        for cfg in self.device_configs.network_interface.iter_mut() {
            let epoll_config = self.epoll_context.allocate_tokens_for_virtio_device(
                TYPE_NET,
                &cfg.iface_id,
                NET_EVENTS_COUNT,
            );

            let allow_mmds_requests = cfg.allow_mmds_requests();

            let rx_rate_limiter = cfg
                .rx_rate_limiter
                .map(vmm_config::RateLimiterConfig::try_into)
                .transpose()
                .map_err(CreateRateLimiter)?;

            let tx_rate_limiter = cfg
                .tx_rate_limiter
                .map(vmm_config::RateLimiterConfig::try_into)
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
        builder: &mut VmmBuilder,
    ) -> result::Result<(), StartMicrovmError> {
        if let Some(cfg) = &self.device_configs.vsock {
            let backend = devices::virtio::vsock::VsockUnixBackend::new(
                u64::from(cfg.guest_cid),
                cfg.uds_path.clone(),
            )
            .map_err(StartMicrovmError::CreateVsockBackend)?;

            let epoll_config = self.epoll_context.allocate_tokens_for_virtio_device(
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

    fn create_guest_memory(&self) -> std::result::Result<GuestMemoryMmap, StartMicrovmError> {
        let mem_size = self
            .vm_config
            .mem_size_mib
            .ok_or(StartMicrovmError::GuestMemoryMmap(
                vm_memory::GuestMemoryError::MemoryNotInitialized,
            ))?
            << 20;
        let arch_mem_regions = arch::arch_memory_regions(mem_size);

        Ok(GuestMemoryMmap::from_ranges(&arch_mem_regions)
            .map_err(StartMicrovmError::GuestMemoryMmap)?)
    }

    fn set_kernel_config(&mut self, kernel_config: KernelConfig) {
        self.kernel_config = Some(kernel_config);
    }

    /// Set the guest boot source configuration.
    pub fn configure_boot_source(&mut self, boot_source_cfg: BootSourceConfig) -> UserResult {
        use BootSourceConfigError::{
            InvalidInitrdPath, InvalidKernelCommandLine, InvalidKernelPath,
            UpdateNotAllowedPostBoot,
        };
        use ErrorKind::User;
        use VmmActionError::BootSource;

        if self.is_instance_initialized() {
            return Err(BootSource(User, UpdateNotAllowedPostBoot));
        }

        let kernel_file = File::open(boot_source_cfg.kernel_image_path)
            .map_err(|e| BootSource(User, InvalidKernelPath(e)))?;

        let initrd_file = match boot_source_cfg.initrd_path {
            None => None,
            Some(path) => Some({
                File::open(path)
                    .map_err(|_| VmmActionError::BootSource(ErrorKind::User, InvalidInitrdPath))?
            }),
        };

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
            initrd_file,
        };
        self.set_kernel_config(kernel_config);

        Ok(())
    }

    /// Set the machine configuration of the microVM.
    pub fn set_vm_configuration(&mut self, machine_config: VmConfig) -> UserResult {
        if self.is_instance_initialized() {
            return Err(VmConfigError::UpdateNotAllowedPostBoot.into());
        }

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

    /// Configures Vmm resources as described by the `config_json` param.
    pub fn configure_from_json(
        &mut self,
        config_json: String,
    ) -> result::Result<(), VmmActionError> {
        let vmm_config = serde_json::from_slice::<VmmConfig>(config_json.as_bytes())
            .unwrap_or_else(|e| {
                error!("Invalid json: {}", e);
                process::exit(i32::from(FC_EXIT_CODE_INVALID_JSON));
            });

        if let Some(logger) = vmm_config.logger {
            let firecracker_version;
            {
                let guard = self.shared_info.read().unwrap();
                LOGGER.set_instance_id(guard.id.clone());
                firecracker_version = guard.vmm_version.clone();
            }
            vmm_config::logger::init_logger(logger, firecracker_version)
                .map_err(|e| VmmActionError::Logger(ErrorKind::User, e))?;
        }
        self.configure_boot_source(vmm_config.boot_source)?;
        for drive_config in vmm_config.block_devices.into_iter() {
            self.insert_block_device(drive_config)?;
        }
        for net_config in vmm_config.net_devices.into_iter() {
            self.insert_net_device(net_config)?;
        }
        if let Some(machine_config) = vmm_config.machine_config {
            self.set_vm_configuration(machine_config)?;
        }
        if let Some(vsock_config) = vmm_config.vsock_device {
            self.set_vsock_device(vsock_config)?;
        }
        Ok(())
    }

    /// Returns the VmConfig.
    pub fn vm_config(&self) -> &VmConfig {
        &self.vm_config
    }

    /// Flush metrics. Defer to inner Vmm if present. We'll move to a variant where the Vmm
    /// simply exposes functionality like getting the dirty pages, and then we'll have the
    /// metrics flushing logic entirely on the outside.
    pub fn flush_metrics(&mut self) -> UserResult {
        if let Some(vmm) = self.vmm.as_mut() {
            vmm.flush_metrics()
        } else {
            // Copied from Vmm.
            LOGGER.log_metrics().map(|_| ()).map_err(|e| {
                let (kind, error_contents) = match e {
                    LoggerError::NeverInitialized(s) => (ErrorKind::User, s),
                    _ => (ErrorKind::Internal, e.to_string()),
                };
                VmmActionError::Logger(kind, LoggerConfigError::FlushMetrics(error_contents))
            })
        }
    }

    /// Injects CTRL+ALT+DEL keystroke combo to the inner Vmm (if present).
    #[cfg(target_arch = "x86_64")]
    pub fn send_ctrl_alt_del(&mut self) -> UserResult {
        if let Some(vmm) = self.vmm.as_mut() {
            vmm.send_ctrl_alt_del()
        } else {
            // TODO: An error would prob be more informative.
            Ok(())
        }
    }

    /// Stops the inner Vmm (if present) and exits the process with the provided exit_code.
    pub fn stop(&mut self, exit_code: i32) {
        if let Some(vmm) = self.vmm.as_mut() {
            // This currently exits the process.
            vmm.stop(exit_code)
        } else {
            process::exit(exit_code)
        }
    }

    /// Creates a new `VmmController`.
    pub fn new(api_shared_info: Arc<RwLock<InstanceInfo>>, api_event_fd: &EventFd) -> Result<Self> {
        let device_configs = DeviceConfigs::new(
            BlockDeviceConfigs::new(),
            NetworkInterfaceConfigs::new(),
            None,
        );

        let mut epoll_context = EpollContext::new()?;
        epoll_context
            .add_epollin_event(api_event_fd, EpollDispatch::VmmActionRequest)
            .expect("Cannot add vmm control_fd to epoll.");

        Ok(VmmController {
            device_configs,
            epoll_context,
            kernel_config: None,
            vm_config: VmConfig::default(),
            shared_info: api_shared_info,
            vmm: None,
        })
    }

    fn load_kernel(
        &mut self,
        vm_memory: &GuestMemoryMmap,
    ) -> std::result::Result<GuestAddress, StartMicrovmError> {
        use StartMicrovmError::*;

        // This is the easy way out of consuming the value of the kernel_cmdline.
        let kernel_config = self.kernel_config.as_mut().ok_or(MissingKernelConfig)?;

        let entry_addr = kernel_loader::load_kernel(
            vm_memory,
            &mut kernel_config.kernel_file,
            arch::get_kernel_start(),
        )
        .map_err(KernelLoader)?;

        Ok(entry_addr)
    }

    fn load_initrd_from_config(
        &mut self,
        vm_memory: &GuestMemoryMmap,
    ) -> std::result::Result<Option<InitrdConfig>, StartMicrovmError> {
        use StartMicrovmError::*;
        Ok(
            match &self
                .kernel_config
                .as_ref()
                .ok_or(MissingKernelConfig)?
                .initrd_file
            {
                Some(f) => {
                    let initrd_file = f.try_clone();
                    if initrd_file.is_err() {
                        return Err(InitrdLoader(LoadInitrdError::ReadInitrd(io::Error::from(
                            io::ErrorKind::InvalidData,
                        ))));
                    }
                    let res = Self::load_initrd(vm_memory, &mut initrd_file.unwrap())?;
                    Some(res)
                }
                None => None,
            },
        )
    }

    /// Loads the initrd from a file into the given memory slice.
    ///
    /// * `vm_memory` - The guest memory the initrd is written to.
    /// * `image` - The initrd image.
    ///
    /// Returns the result of initrd loading
    fn load_initrd<F>(
        vm_memory: &GuestMemoryMmap,
        image: &mut F,
    ) -> std::result::Result<InitrdConfig, LoadInitrdError>
    where
        F: Read + Seek,
    {
        use LoadInitrdError::*;

        let size: usize;
        // Get the image size
        match image.seek(SeekFrom::End(0)) {
            Err(e) => return Err(ReadInitrd(e)),
            Ok(0) => {
                return Err(ReadInitrd(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Initrd image seek returned a size of zero",
                )))
            }
            Ok(s) => size = s as usize,
        };
        // Go back to the image start
        image.seek(SeekFrom::Start(0)).map_err(ReadInitrd)?;

        // Get the target address
        let address = arch::initrd_load_addr(vm_memory, size).map_err(|_| LoadInitrd)?;

        // Load the image into memory
        vm_memory
            .read_from(GuestAddress(address), image, size)
            .map_err(|_| LoadInitrd)?;

        Ok(InitrdConfig {
            address: GuestAddress(address),
            size,
        })
    }

    /// Starts a microVM based on the current configuration.
    pub fn start_microvm(
        &mut self,
        vmm_seccomp_filter: BpfProgram,
        vcpu_seccomp_filter: BpfProgram,
    ) -> UserResult {
        if self.is_instance_initialized() {
            // Reusing this error to represent that we've called this method before.
            return Err(StartMicrovmError::MicroVMAlreadyRunning.into());
        }

        // Setting this here to signal a start_microvm action has already been attempted.
        self.shared_info
            .write()
            .expect("Failed to start microVM because shared info couldn't be written due to poisoned lock")
            .started = true;

        let guest_memory = self.create_guest_memory()?;
        let kernel_entry_addr = self.load_kernel(&guest_memory)?;
        let initrd = self.load_initrd_from_config(&guest_memory)?;

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

        let builder_config = VmmBuilderConfig {
            guest_memory,
            entry_addr: kernel_entry_addr,
            kernel_cmdline: kernel_config.cmdline,
            initrd,
            vcpu_config,
            vmm_seccomp_filter,
            vcpu_seccomp_filter,
        };

        let mut builder = VmmBuilder::new(&mut self.epoll_context, builder_config)?;

        self.attach_block_devices(&mut builder)?;
        self.attach_net_devices(&mut builder)?;
        self.attach_vsock_device(&mut builder)?;

        self.vmm = Some(builder.run(&mut self.epoll_context)?);

        Ok(())
    }

    /// Wait for and dispatch events. Will defer to the inner Vmm loop after it's started.
    pub fn run_event_loop(&mut self) -> Result<EventLoopExitReason> {
        if let Some(vmm) = self.vmm.as_mut() {
            vmm.run_event_loop(&mut self.epoll_context)
        } else {
            // The only possible event so far is getting a command from the API server.
            let event = self.epoll_context.get_event()?;
            match self.epoll_context.dispatch_table[event.data as usize] {
                Some(EpollDispatch::VmmActionRequest) => Ok(EventLoopExitReason::ControlAction),
                // TODO: Very unlikely this happens. Temporary solution untill we switch to polly.
                _ => panic!("Unexpected VmmController epoll event"),
            }
        }
    }

    /// Triggers a rescan of the host file backing the emulated block device with id `drive_id`.
    pub fn rescan_block_device(&mut self, drive_id: &str) -> UserResult {
        // Rescan can only happen after the guest is booted.
        if let Some(vmm) = self.vmm.as_mut() {
            for drive_config in self.device_configs.block.config_list.iter() {
                if drive_config.drive_id != *drive_id {
                    continue;
                }

                // Use seek() instead of stat() (std::fs::Metadata) to support block devices.
                let new_size = File::open(&drive_config.path_on_host)
                    .and_then(|mut f| f.seek(SeekFrom::End(0)))
                    .map_err(|_| DriveError::BlockDeviceUpdateFailed)?;
                if new_size % virtio::block::SECTOR_SIZE != 0 {
                    warn!(
                        "Disk size {} is not a multiple of sector size {}; \
                         the remainder will not be visible to the guest.",
                        new_size,
                        virtio::block::SECTOR_SIZE
                    );
                }

                return match vmm.get_bus_device(DeviceType::Virtio(TYPE_BLOCK), drive_id) {
                    Some(device) => {
                        let data = devices::virtio::build_config_space(new_size);
                        let mut busdev = device.lock().map_err(|_| {
                            VmmActionError::from(DriveError::BlockDeviceUpdateFailed)
                        })?;

                        busdev.write(MMIO_CFG_SPACE_OFF, &data[..]);
                        busdev.interrupt(devices::virtio::VIRTIO_MMIO_INT_CONFIG);

                        Ok(())
                    }
                    None => Err(VmmActionError::from(DriveError::BlockDeviceUpdateFailed)),
                };
            }
        } else {
            return Err(DriveError::OperationNotAllowedPreBoot.into());
        }

        Err(VmmActionError::from(DriveError::InvalidBlockDeviceID))
    }

    fn update_drive_handler(
        &mut self,
        drive_id: &str,
        disk_image: File,
    ) -> result::Result<(), DriveError> {
        // The unwrap is safe because this is only called after the inner Vmm has booted.
        let handler = self
            .epoll_context
            .get_device_handler_by_device_id::<virtio::BlockEpollHandler>(TYPE_BLOCK, drive_id)
            .map_err(|_| DriveError::EpollHandlerNotFound)?;

        handler
            .update_disk_image(disk_image)
            .map_err(|_| DriveError::BlockDeviceUpdateFailed)
    }

    /// Updates the path of the host file backing the emulated block device with id `drive_id`.
    pub fn set_block_device_path(&mut self, drive_id: String, path_on_host: String) -> UserResult {
        // Get the block device configuration specified by drive_id.
        let block_device_index = self
            .device_configs
            .block
            .get_index_of_drive_id(&drive_id)
            .ok_or(DriveError::InvalidBlockDeviceID)?;

        let file_path = PathBuf::from(path_on_host);
        // Try to open the file specified by path_on_host using the permissions of the block_device.
        let disk_file = OpenOptions::new()
            .read(true)
            .write(!self.device_configs.block.config_list[block_device_index].is_read_only())
            .open(&file_path)
            .map_err(|_| DriveError::CannotOpenBlockDevice)?;

        // Update the path of the block device with the specified path_on_host.
        self.device_configs.block.config_list[block_device_index].path_on_host = file_path;

        // When the microvm is running, we also need to update the drive handler and send a
        // rescan command to the drive.
        if self.is_instance_initialized() {
            self.update_drive_handler(&drive_id, disk_file)?;
            self.rescan_block_device(&drive_id)?;
        }
        Ok(())
    }

    /// Updates configuration for an emulated net device as described in `new_cfg`.
    pub fn update_net_device(&mut self, new_cfg: NetworkInterfaceUpdateConfig) -> UserResult {
        if !self.is_instance_initialized() {
            // VM not started yet, so we only need to update the device configs, not the actual
            // live device.
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
        } else {
            // If we got to here, the VM is running, so the unwrap is safe. We need to update the
            // live device.

            let handler = self
                .epoll_context
                .get_device_handler_by_device_id::<virtio::NetEpollHandler>(
                    TYPE_NET,
                    &new_cfg.iface_id,
                )
                .map_err(NetworkInterfaceError::EpollHandlerNotFound)?;

            macro_rules! get_handler_arg {
                ($rate_limiter: ident, $metric: ident) => {{
                    new_cfg
                        .$rate_limiter
                        .map(|rl| rl.$metric.map(vmm_config::TokenBucketConfig::into))
                        .unwrap_or(None)
                }};
            }

            handler.patch_rate_limiters(
                get_handler_arg!(rx_rate_limiter, bandwidth),
                get_handler_arg!(rx_rate_limiter, ops),
                get_handler_arg!(tx_rate_limiter, bandwidth),
                get_handler_arg!(tx_rate_limiter, ops),
            );
        }

        Ok(())
    }
}

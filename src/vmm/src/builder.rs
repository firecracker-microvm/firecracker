// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use timerfd::{ClockId, SetTimeFlags, TimerFd, TimerState};

use std::fs::{File, OpenOptions};
use std::time::Duration;

use super::{
    EpollContext, EpollDispatch, KvmContext, MMIODeviceManager, PortIODeviceManager, Vcpu,
    VcpuConfig, Vm, Vmm,
};

use devices::virtio::vsock::{TYPE_VSOCK, VSOCK_EVENTS_COUNT};
use devices::virtio::{MmioDevice, BLOCK_EVENTS_COUNT, NET_EVENTS_COUNT, TYPE_BLOCK, TYPE_NET};
use error::*;

use kernel::{cmdline as kernel_cmdline, loader as kernel_loader};
use logger::{Metric, LOGGER, METRICS};
use memory_model::{GuestAddress, GuestMemory};
use polly::event_manager::EventManager;
use resources::VmResources;
use utils::time::TimestampUs;
use vmm_config;
use vmm_config::boot_source::DEFAULT_KERNEL_CMDLINE;

const WRITE_METRICS_PERIOD_SECONDS: u64 = 60;

/// Enables pre-boot setup, instantiation and real time configuration of a Firecracker VMM.
pub struct VmmBuilder<'a> {
    vm_resources: &'a VmResources,
    seccomp_level: u32,
    cmdline: Option<kernel::cmdline::Cmdline>,
}

impl<'a> VmmBuilder<'a> {
    /// Creates a new `VmmBuilder`.
    pub fn new(vm_resources: &'a VmResources, seccomp_level: u32) -> Self {
        VmmBuilder {
            vm_resources,
            seccomp_level,
            cmdline: None,
        }
    }

    // TODO: make this consume self, but also be resilient to errors.
    /// Builds and starts a microVM based on the current configuration.
    pub fn build_microvm(
        mut self,
        epoll_context: &mut EpollContext,
    ) -> std::result::Result<Vmm, VmmActionError> {
        let guest_memory = self.create_guest_memory()?;
        let kernel_entry_addr = self.load_kernel(&guest_memory)?;

        // The unwraps are ok to use because the values are initialized using defaults if not
        // supplied by the user.
        let vcpu_config = VcpuConfig {
            vcpu_count: self.vm_resources.vm_config().vcpu_count.unwrap(),
            ht_enabled: self.vm_resources.vm_config().ht_enabled.unwrap(),
            cpu_template: self.vm_resources.vm_config().cpu_template,
        };

        let builder_config = VmmBuilderzConfig {
            guest_memory,
            entry_addr: kernel_entry_addr,
            kernel_cmdline: self.cmdline.as_ref().unwrap().clone(),
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
        let mem_size =
            self.vm_resources
                .vm_config()
                .mem_size_mib
                .ok_or(StartMicrovmError::GuestMemory(
                    memory_model::GuestMemoryError::MemoryNotInitialized,
                ))?
                << 20;
        let arch_mem_regions = arch::arch_memory_regions(mem_size);

        Ok(GuestMemory::new(&arch_mem_regions).map_err(StartMicrovmError::GuestMemory)?)
    }

    // TODO: break this function, kernel-cfg is no longer a thing.
    fn load_kernel(
        &mut self,
        guest_memory: &GuestMemory,
    ) -> std::result::Result<GuestAddress, StartMicrovmError> {
        let boot_src_cfg = self
            .vm_resources
            .boot_source()
            .ok_or(StartMicrovmError::MissingKernelConfig)?;

        // FIXME: use the right error here.
        let mut kernel_file =
            File::open(&boot_src_cfg.kernel_image_path).map_err(StartMicrovmError::VcpuSpawn)?;
        let mut cmdline = kernel::cmdline::Cmdline::new(arch::CMDLINE_MAX_SIZE);
        let boot_args = match boot_src_cfg.boot_args.as_ref() {
            None => DEFAULT_KERNEL_CMDLINE,
            Some(str) => str.as_str(),
        };
        cmdline
            .insert_str(boot_args)
            .map_err(|e| StartMicrovmError::KernelCmdline(e.to_string()))?;

        let entry_addr =
            kernel_loader::load_kernel(guest_memory, &mut kernel_file, arch::get_kernel_start())
                .map_err(StartMicrovmError::KernelLoader)?;

        self.cmdline = Some(cmdline);

        Ok(entry_addr)
    }

    fn attach_block_devices(
        &mut self,
        builder: &mut VmmBuilderz,
        epoll_context: &mut EpollContext,
    ) -> std::result::Result<(), StartMicrovmError> {
        use StartMicrovmError::*;

        // If no PARTUUID was specified for the root device, try with the /dev/vda.
        if self.vm_resources.block.has_root_block_device()
            && !self.vm_resources.block.has_partuuid_root()
        {
            let kernel_cmdline = builder.kernel_cmdline_mut();

            kernel_cmdline.insert_str("root=/dev/vda")?;

            let flags = if self.vm_resources.block.has_read_only_root() {
                "ro"
            } else {
                "rw"
            };

            kernel_cmdline.insert_str(flags)?;
        }

        for drive_config in self.vm_resources.block.config_list.iter() {
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

        for cfg in self.vm_resources.network_interface.iter() {
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
        if let Some(cfg) = &self.vm_resources.vsock {
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
